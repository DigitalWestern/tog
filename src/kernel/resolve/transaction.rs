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
//!    A journal at `.tog/journal/<ecosystem>.json` (under `.tog/`, which
//!    projects do not commit, and outside `.tog/resolution/`, which they
//!    do) names the originals object before it is rooted, so a process
//!    killed while the tool runs leaves nothing rooted that recovery cannot
//!    find and release.
//! 2. **Journal.** Before the first project write, the journal lists every
//!    target: its temporary name, pre-run digest, new digest and state. The
//!    file and its directory are fsynced. The journal's presence means
//!    "publication may be incomplete".
//! 3. **Swap, then compare.** Each target's new bytes go to a temporary
//!    beside it, which is atomically exchanged with the target
//!    (`renameat2(RENAME_EXCHANGE)`). The temporary now holds exactly what
//!    the target held an instant before; if its digest is not the pre-run
//!    digest, somebody edited the file during the run, so the two are
//!    exchanged back (their edit is restored exactly) and the transaction
//!    fails. An absent target is created with `RENAME_NOREPLACE`, which
//!    fails if anything appeared meanwhile.
//! 4. **Commit.** Once the receipt is in place, the journal is marked
//!    committed and the displaced temporaries are deleted.
//! 5. **Finish.** The project's files are now final, so the journal is
//!    marked finished, the originals are released, and only then are the
//!    journal and the directories the transaction created deleted. A
//!    release that fails leaves the finished journal, and the next
//!    recovery releases again. A held journal (nothing was published) goes
//!    the same way without being rewritten.
//!
//! Any failure during step 3 undoes every target in reverse, then
//! finishes, and recovery after a crash does the same from the journal.
//! Recovery trusts a journal only in the directory it was asked about
//! (never an ancestor), only when the originals object it names is in this
//! store and rooted to this project with an identity that lists exactly its
//! targets and pre-run digests, and only for temporaries named the way this
//! module names them. A held or finished journal touches no target, so its
//! originals need only be of the right kind, or gone (never committed, or
//! collected after the release that preceded a crash), and when they are
//! gone the journal must name this store as the one that wrote it.
//! Anything else is refused with the journal's path, and nothing is
//! touched. Every holder of a project's journal also holds an `flock` on
//! the project directory itself, so two tog processes using different
//! stores cannot undo each other's publication. Both decide by
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

mod recovery;

use recovery::{
    finish, finish_committed, is_journal_name, lock_project_dir, narrate, recover_locked, undo,
};
pub use recovery::{has_pending_journal, recover_project};

/// The project directory holding receipts.
pub const RESOLUTION_DIR: &str = ".tog/resolution";
/// The project directory holding publication journals: under `.tog/`, but
/// not under `.tog/resolution/`, which projects commit.
pub const JOURNAL_DIR: &str = ".tog/journal";
const JOURNAL_SCHEMA: &str = "resolution-journal/1";
const ORIGINALS_KIND: &str = "resolution-originals";
const ORIGINALS_SCHEMA: &str = "resolution-originals/1";
const ABSENT: &str = "absent";

/// The receipt a door publishes for `ecosystem`, relative to the lock root.
pub fn receipt_path(ecosystem: &str) -> PathBuf {
    Path::new(RESOLUTION_DIR).join(format!("{ecosystem}.json"))
}

fn journal_name(ecosystem: &str) -> String {
    format!("{ecosystem}.json")
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

/// How a publication ended when it did not fail.
#[derive(Debug)]
pub enum Published {
    /// Published, and every temporary, the journal and the originals'
    /// root are gone.
    Clean,
    /// Published (the journal says committed or finished), but cleaning up
    /// after it failed. The journal stays and the next recovery finishes;
    /// nothing published is taken back.
    CleanupPending(io::Error),
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
    /// The `flock` on the project directory, held for the whole run.
    _dir_lock: fs::File,
    ecosystem: String,
    targets: Vec<Held>,
    /// The originals object, named in the journal before it is rooted.
    originals: String,
    /// `.tog` and `.tog/journal`, when this transaction created them.
    created_at_hold: Vec<String>,
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
        let dir_lock = lock_project_dir(&root)?;
        recover_locked(store, activity, &root, &project_lock)?;
        let mut transaction = Transaction {
            store,
            activity,
            root,
            lock: project_lock,
            _dir_lock: dir_lock,
            ecosystem: spec.ecosystem.to_string(),
            targets: Vec::new(),
            originals: String::new(),
            created_at_hold: Vec::new(),
            finished: true,
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

    /// Commit the originals as one store object (even when every target
    /// is absent: recovery trusts a journal only through it) and root it
    /// for this project. The `held` journal naming it is written first,
    /// so a process killed at any later point leaves a journal recovery
    /// finds.
    fn commit_originals(&mut self, copies: Vec<Vec<u8>>) -> io::Result<()> {
        let mut targets = Vec::new();
        for held in &self.targets {
            targets.push((
                path_text(&held.relative)?.to_string(),
                held.original.as_ref().map(|original| original.sha256),
            ));
        }
        let run = hex::encode(crate::kernel::fsroot::urandom_bytes(16)?);
        let identity = originals_identity(&self.ecosystem, &run, &targets);
        self.originals = identity.object_id();
        // From here on, dropping the transaction releases what it holds
        // (each step of the release tolerates what never happened).
        self.finished = false;
        self.created_at_hold = create_missing_dirs(&self.root, Path::new(JOURNAL_DIR))?
            .iter()
            .map(|dir| path_text(dir).map(str::to_string))
            .collect::<io::Result<_>>()?;
        write_journal(
            &self.journal_dir()?,
            &self.journal(JournalState::Held, Vec::new()),
        )?;
        let stage = self.store.stage_with_activity(self.activity)?;
        if let Err(error) = self.write_originals(&stage, copies) {
            let _ = store::remove_tree(&stage);
            return Err(error);
        }
        self.store.commit_with_activity_and_deps(
            self.activity,
            &identity,
            &stage,
            &[],
            &ObjectDeps::new(),
        )?;
        self.store.register_root_parts_with_project_lock(
            self.activity,
            &self.root,
            BTreeSet::from([self.originals.clone()]),
            BTreeSet::new(),
            &self.lock,
        )?;
        Ok(())
    }

    fn write_originals(&self, stage: &Path, copies: Vec<Vec<u8>>) -> io::Result<()> {
        let mut copies = copies.into_iter();
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
        }
        Ok(())
    }

    fn journal(&self, state: JournalState, targets: Vec<JournalTarget>) -> Journal {
        Journal {
            schema: JOURNAL_SCHEMA.to_string(),
            ecosystem: self.ecosystem.clone(),
            state,
            originals: self.originals.clone(),
            store: Some(store_name(self.store)),
            created_dirs: self.created_at_hold.clone(),
            targets,
        }
    }

    fn journal_dir(&self) -> io::Result<ProjectRoot> {
        self.root.subdir(Path::new(JOURNAL_DIR))?.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("{} vanished", self.root.path().join(JOURNAL_DIR).display()),
            )
        })
    }

    /// Publish: replace each held target that has a new version (the
    /// outputs the tool changed, then `receipt`), all or nothing. A held
    /// output the tool left alone must still hold its pre-run bytes.
    ///
    /// Once the journal says committed the publication has happened, so a
    /// failure while cleaning up after it is not an error: it comes back
    /// as [`Published::CleanupPending`], the journal stays (committed, or
    /// finished once the temporaries are gone), and the next recovery
    /// finishes the cleanup.
    pub fn publish(mut self, outputs: &Outputs, receipt: Option<&[u8]>) -> io::Result<Published> {
        let plan = self.plan(outputs, receipt)?;
        let mut created = self.created_at_hold.clone();
        for dir in self.prepare_dirs(&plan)? {
            created.push(path_text(&dir)?.to_string());
        }
        let mut journal = self.journal(
            JournalState::Publishing,
            plan.iter().map(|entry| entry.journal.clone()).collect(),
        );
        journal.created_dirs = created;
        let journals = self.journal_dir()?;
        let outcome = (|| {
            write_journal(&journals, &journal)?;
            fault(FaultPoint::Journaled)?;
            for (index, entry) in plan.iter().enumerate() {
                self.swap(entry, index)?;
                journal.targets[index].state = TargetState::Swapped;
                write_journal(&journals, &journal)?;
                fault(FaultPoint::Marked(index))?;
            }
            self.verify_unpublished(&plan)?;
            fault(FaultPoint::Verified)?;
            journal.state = JournalState::Committed;
            write_journal(&journals, &journal)?;
            fault(FaultPoint::Committed)
        })();
        match outcome {
            Ok(()) => {
                self.finished = true;
                match finish_committed(self.store, self.activity, &self.root, &self.lock, &journal)
                {
                    Ok(()) => Ok(Published::Clean),
                    Err(error) if is_crash(&error) => Err(error),
                    Err(error) => Ok(Published::CleanupPending(error)),
                }
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
                        self.finished = true;
                        narrate(self.root.path(), &notes, "undone");
                        match finish(self.store, self.activity, &self.root, &self.lock, &journal) {
                            Ok(()) => Err(error),
                            Err(cleanup) if is_crash(&cleanup) => Err(cleanup),
                            Err(cleanup) => Err(io::Error::new(
                                error.kind(),
                                format!(
                                    "{error}; the partial publication was undone, but \
                                     cleaning up after it failed ({cleanup}), so the journal \
                                     {} was kept and the next tog command in this project \
                                     will finish it",
                                    self.root
                                        .path()
                                        .join(JOURNAL_DIR)
                                        .join(journal_name(&self.ecosystem))
                                        .display()
                                ),
                            )),
                        }
                    }
                    Err(undo_error) => {
                        // The journal stays, and so does the originals'
                        // root: the next writing command recovers.
                        self.finished = true;
                        Err(io::Error::new(
                            error.kind(),
                            format!(
                                "{error}; undoing the partial publication also failed \
                                 ({undo_error}), so the journal {} was kept and the next \
                                 tog command in this project will finish undoing it",
                                self.root
                                    .path()
                                    .join(JOURNAL_DIR)
                                    .join(journal_name(&self.ecosystem))
                                    .display()
                            ),
                        ))
                    }
                }
            }
        }
    }

    /// Give up before publishing: nothing in the project was touched, so
    /// the held journal and the originals' root are released.
    pub fn abandon(mut self) -> io::Result<()> {
        self.finished = true;
        self.release()
    }

    fn release(&self) -> io::Result<()> {
        let journal = self.journal(JournalState::Held, Vec::new());
        finish(self.store, self.activity, &self.root, &self.lock, &journal)
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
            let bytes = if held.receipt {
                match receipt {
                    Some(bytes) => bytes.to_vec(),
                    None => continue,
                }
            } else {
                match outputs.get(&held.relative) {
                    Some(file) => outputs.contents(file)?,
                    None => continue,
                }
            };
            // A replaced file keeps its own mode; a created one gets the
            // ordinary file mode under this process's umask, never whatever
            // bits the tool left on its copy.
            let mode = held
                .original
                .as_ref()
                .map_or_else(new_file_mode, |original| original.mode);
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

    /// Create every missing parent of a planned target (`.tog/resolution`
    /// for the receipt), returning the directories created (outermost
    /// first).
    fn prepare_dirs(&self, plan: &[Planned]) -> io::Result<Vec<PathBuf>> {
        let mut created = Vec::new();
        for entry in plan {
            if let Some(parent) = self.targets[entry.target].relative.parent() {
                if !parent.as_os_str().is_empty() {
                    created.extend(create_missing_dirs(&self.root, parent)?);
                }
            }
        }
        Ok(created)
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
    /// The targets are held and the originals named; nothing in the
    /// project has been touched. Recovery releases the originals.
    Held,
    /// Targets are being swapped. Recovery undoes every target, then
    /// finishes.
    Publishing,
    /// Every target is published; displaced temporaries may remain.
    /// Recovery deletes them, then finishes.
    Committed,
    /// The project's files are final (published or undone) and the
    /// temporaries are gone: only the originals' root and the journal
    /// remain. Recovery releases the originals, then deletes the journal.
    /// Trusted without its originals rooted, since the release may have
    /// happened just before a crash.
    Finished,
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
    /// The originals object's id.
    originals: String,
    /// The store that wrote the journal: its canonical root. Recovery
    /// trusts a held or finished journal whose originals are not in the
    /// store only when it names that store, so another store's journal is
    /// refused rather than consumed while its originals stay rooted there.
    /// Absent in a journal written before the field existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    store: Option<String>,
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

/// Remove the directories `journal` says its transaction created, deepest
/// first, each only if it is empty.
fn remove_created_dirs(root: &ProjectRoot, journal: &Journal) -> io::Result<()> {
    let mut dirs: Vec<&String> = journal.created_dirs.iter().collect();
    dirs.sort_by_key(|dir| std::cmp::Reverse(Path::new(dir.as_str()).components().count()));
    for dir in dirs {
        let dir = Path::new(dir.as_str());
        check_target(dir)?;
        if let Ok((parent, name)) = parent_of(root, dir) {
            remove_empty_dir(parent.as_raw_fd(), &name)?;
        }
    }
    Ok(())
}

/// Create `relative` and its missing parents through the held root,
/// returning those created (outermost first).
fn create_missing_dirs(root: &ProjectRoot, relative: &Path) -> io::Result<Vec<PathBuf>> {
    let mut created = Vec::new();
    let mut prefix = PathBuf::new();
    for component in relative.components() {
        prefix.push(component);
        if root.subdir(&prefix)?.is_none() {
            root.create_dir_all(&prefix)?;
            created.push(prefix.clone());
        }
    }
    Ok(created)
}

/// How a journal names the store that wrote it.
fn store_name(store: &Store) -> String {
    store.root.to_string_lossy().into_owned()
}

fn journal_error(journal: &Journal, detail: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!(
            "the {} resolution journal in {JOURNAL_DIR} cannot be recovered: {detail}; \
             inspect the files it names, then delete it",
            journal.ecosystem
        ),
    )
}

fn parse_digest(text: &str) -> Option<[u8; 32]> {
    hex::decode(text)
        .ok()
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
}

/// Read one journal. A journal that does not parse is refused with its
/// exact path; it blocks only the commands that write this project.
fn read_journal(journals: &ProjectRoot, name: &str) -> io::Result<Journal> {
    let shown = journals.path().join(name);
    let refused = |why: String| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "the resolution journal {} is {why}, so tog will not act on it. If no tog \
                 command was interrupted in this project, delete {}; otherwise inspect the \
                 files it names first",
                shown.display(),
                shown.display()
            ),
        )
    };
    let bytes = journals
        .read_file(Path::new(name))
        .map_err(|error| refused(format!("unreadable ({error})")))?;
    let bytes = bytes.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("{} vanished", shown.display()),
        )
    })?;
    let journal: Journal =
        serde_json::from_slice(&bytes).map_err(|error| refused(format!("malformed ({error})")))?;
    if journal.schema != JOURNAL_SCHEMA || journal_name(&journal.ecosystem) != name {
        return Err(refused(format!(
            "not a {JOURNAL_SCHEMA} journal for its name"
        )));
    }
    Ok(journal)
}

/// `.<ecosystem>.json.<16 hex>.tmp`, as `write_journal` names its
/// temporaries.
fn is_journal_temp(name: &str) -> bool {
    name.strip_prefix('.')
        .and_then(|rest| rest.strip_suffix(".tmp"))
        .and_then(|rest| rest.rsplit_once('.'))
        .is_some_and(|(journal, hex)| {
            is_journal_name(journal)
                && hex.len() == 16
                && hex
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
}

/// Replace the journal atomically: temporary, fsync, rename, fsync the
/// directory.
fn write_journal(journals: &ProjectRoot, journal: &Journal) -> io::Result<()> {
    let bytes = serde_json::to_vec_pretty(journal).map_err(io::Error::other)?;
    let name = journal_name(&journal.ecosystem);
    let temp = format!(
        ".{name}.{}.tmp",
        hex::encode(crate::kernel::fsroot::urandom_bytes(8)?)
    );
    write_temp(journals.as_raw_fd(), OsStr::new(&temp), &bytes, 0o644)?;
    rename_replace(journals.as_raw_fd(), OsStr::new(&temp), OsStr::new(&name))?;
    store::fsync_directory(journals.as_raw_fd())
}

fn remove_journal(journals: &ProjectRoot, ecosystem: &str) -> io::Result<()> {
    unlink_at(journals.as_raw_fd(), OsStr::new(&journal_name(ecosystem)))?;
    store::fsync_directory(journals.as_raw_fd())
}

/// The mode of a file a publication creates: 0644 under this process's
/// umask, read from `/proc/self/status` (setting the umask to read it
/// would race other threads). Without it, 0644.
pub(crate) fn new_file_mode() -> u32 {
    let umask = fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status.lines().find_map(|line| {
                line.strip_prefix("Umask:")
                    .and_then(|value| u32::from_str_radix(value.trim(), 8).ok())
            })
        })
        .unwrap_or(0o022);
    0o644 & !umask
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
    /// In `finish`, before the originals are released.
    Releasing,
    /// In `finish`, after the release and before the journal is deleted.
    Released,
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
            store: Store::for_test(root.canonicalize().unwrap()),
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

    fn crash_at(at: FaultPoint) -> impl FnMut(FaultPoint) -> Fault + 'static {
        move |point| {
            if point == at {
                Fault::Crash
            } else {
                Fault::Continue
            }
        }
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
    ) -> io::Result<Published> {
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
                forbidden: &[],
            },
        )?;
        let staged = snapshot.lock_root().staged.clone();
        fs::write(staged.join("package.json"), NEW_MANIFEST)?;
        fs::write(staged.join("package-lock.json"), NEW_LOCK)?;
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(
                staged.join("package-lock.json"),
                fs::Permissions::from_mode(0o777),
            )?;
        }
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
        assert!(error.to_string().contains("nothing was changed"), "{error}");
        assert!(has_pending_journal(&fx.project));
        assert_eq!(read(&fx, "package.json").as_deref(), Some(NEW_MANIFEST));
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

    /// A journal in a parent directory is never acted on from a project
    /// below it: recovery looks only at the project it was asked about.
    #[test]
    fn a_journal_in_a_parent_is_not_recovered_from_a_member() {
        let fx = fixture("member", true);
        fs::create_dir_all(fx.project.join("member")).unwrap();
        let _ = run_door(&fx, |_| {}, crash_at(FaultPoint::Marked(1)));
        assert!(!has_pending_journal(&fx.project.join("member")));
        let activity = fx.store.activity(ActivityMode::Shared).unwrap();
        let notes = recover_project(&fx.store, &activity, &fx.project.join("member")).unwrap();
        assert!(notes.is_empty(), "{notes:?}");
        assert_eq!(read(&fx, "package.json").as_deref(), Some(NEW_MANIFEST));
        assert!(has_pending_journal(&fx.project));
    }

    fn journal_path(fx: &Fixture) -> PathBuf {
        fx.project.join(JOURNAL_DIR).join("npm.json")
    }

    fn edit_journal(fx: &Fixture, edit: impl FnOnce(&mut serde_json::Value)) {
        let path = journal_path(fx);
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        edit(&mut value);
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    }

    fn recover_err(fx: &Fixture) -> io::Error {
        let activity = fx.store.activity(ActivityMode::Shared).unwrap();
        recover_project(&fx.store, &activity, &fx.project).unwrap_err()
    }

    /// The journal lives under `.tog/journal/`, never in
    /// `.tog/resolution/`, which projects commit.
    #[test]
    fn the_journal_is_outside_the_committed_resolution_directory() {
        let fx = fixture("journal-place", true);
        let _ = run_door(&fx, |_| {}, crash_at(FaultPoint::Marked(0)));
        assert!(journal_path(&fx).is_file());
        for entry in fs::read_dir(fx.project.join(RESOLUTION_DIR)).unwrap() {
            let name = entry.unwrap().file_name().into_string().unwrap();
            assert!(!name.contains("journal"), "{name}");
        }
    }

    /// A committed journal whose temporary names another file is refused:
    /// the file is not deleted.
    #[test]
    fn a_journal_naming_a_foreign_temporary_is_refused_and_deletes_nothing() {
        let fx = fixture("forged-temp", true);
        let _ = run_door(&fx, |_| {}, crash_at(FaultPoint::Committed));
        fs::write(fx.project.join("victim.txt"), b"mine\n").unwrap();
        for forged in [
            "victim.txt",
            "../victim.txt",
            ".victim.txt.tog-0123456789abcdef.tmp",
        ] {
            edit_journal(&fx, |journal| {
                journal["targets"][0]["temp"] = forged.into();
            });
            let error = recover_err(&fx);
            assert!(
                error.to_string().contains("nothing was changed"),
                "{forged}: {error}"
            );
            assert!(
                error.to_string().contains(".tog/journal/npm.json"),
                "{error}"
            );
            assert_eq!(read(&fx, "victim.txt").as_deref(), Some(&b"mine\n"[..]));
        }
        edit_journal(&fx, |journal| {
            journal["targets"][0]["target"] = "../victim.txt".into();
        });
        assert!(recover_err(&fx).to_string().contains("nothing was changed"));
        assert_eq!(read(&fx, "victim.txt").as_deref(), Some(&b"mine\n"[..]));
    }

    /// A journal whose originals object is not in this store, or not
    /// rooted to this project, or does not list the journal's targets, is
    /// refused and nothing is touched. That covers a journal planted in a
    /// project, copied from another one, or left by a run with another
    /// store.
    #[test]
    fn a_journal_without_matching_rooted_originals_is_refused() {
        let fx = fixture("forged-originals", true);
        let _ = run_door(&fx, |_| {}, crash_at(FaultPoint::Marked(1)));
        let good: serde_json::Value =
            serde_json::from_slice(&fs::read(journal_path(&fx)).unwrap()).unwrap();
        let cases: Vec<Box<dyn Fn(&mut serde_json::Value)>> = vec![
            Box::new(|journal| journal["originals"] = format!("{}-npm-1", "a".repeat(40)).into()),
            Box::new(|journal| journal["targets"][0]["original"] = "0".repeat(64).into()),
            Box::new(|journal| journal["targets"][1]["target"] = "other.json".into()),
        ];
        for edit in cases {
            let mut journal = good.clone();
            edit(&mut journal);
            fs::write(journal_path(&fx), serde_json::to_vec(&journal).unwrap()).unwrap();
            let error = recover_err(&fx);
            assert!(error.to_string().contains("nothing was changed"), "{error}");
            assert_eq!(read(&fx, "package.json").as_deref(), Some(NEW_MANIFEST));
        }
        // Rooted to another project only: copy this project's journal there.
        let other = fixture("forged-elsewhere", true);
        fs::create_dir_all(other.project.join(JOURNAL_DIR)).unwrap();
        fs::write(journal_path(&other), serde_json::to_vec(&good).unwrap()).unwrap();
        let other = Fixture {
            store: fx.store.clone(),
            project: other.project.clone(),
            _temp: other._temp,
        };
        let error = recover_err(&other);
        assert!(
            error.to_string().contains("not rooted to this project"),
            "{error}"
        );
        assert_eq!(read(&other, "package.json").as_deref(), Some(OLD_MANIFEST));
        // The real journal still recovers.
        fs::write(journal_path(&fx), serde_json::to_vec(&good).unwrap()).unwrap();
        recover(&fx);
        assert_original(&fx, Some(OLD_RECEIPT));
    }

    #[test]
    fn a_malformed_journal_is_refused_naming_its_path() {
        let fx = fixture("malformed", true);
        fs::create_dir_all(fx.project.join(JOURNAL_DIR)).unwrap();
        fs::write(journal_path(&fx), b"{not json").unwrap();
        let error = recover_err(&fx);
        let text = error.to_string();
        assert!(
            text.contains(&journal_path(&fx).display().to_string()),
            "{text}"
        );
        assert!(text.contains("delete"), "{text}");
        assert_eq!(read(&fx, "package.json").as_deref(), Some(OLD_MANIFEST));
    }

    /// A target that passed the compare (`swapped`) is restored from the
    /// stored copy when its temporary no longer holds the pre-run bytes,
    /// so a planted temporary is never exchanged in.
    #[test]
    fn a_planted_temporary_for_a_swapped_target_is_never_exchanged_in() {
        let fx = fixture("planted-bytes", true);
        let _ = run_door(&fx, |_| {}, crash_at(FaultPoint::Marked(0)));
        let temp = fs::read_dir(&fx.project)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| path.to_string_lossy().ends_with(".tmp"))
            .unwrap();
        fs::write(&temp, b"planted\n").unwrap();
        recover(&fx);
        assert_original(&fx, Some(OLD_RECEIPT));
    }

    /// Cleanup failing after the commit point is not a failed publication:
    /// the outputs and receipt stay, the journal stays committed, and
    /// recovery finishes.
    #[test]
    fn a_cleanup_failure_after_commit_is_published_with_cleanup_pending() {
        let fx = fixture("cleanup-pending", true);
        let published = run_door(
            &fx,
            |_| {},
            |point| {
                if point == FaultPoint::TempsRemoved {
                    Fault::Fail
                } else {
                    Fault::Continue
                }
            },
        )
        .unwrap();
        assert!(
            matches!(published, Published::CleanupPending(_)),
            "{published:?}"
        );
        assert_eq!(read(&fx, "package-lock.json").as_deref(), Some(NEW_LOCK));
        assert!(has_pending_journal(&fx.project));
        // It failed before the finished journal was written, so the
        // committed one stands.
        assert_eq!(journal_state(&fx).as_deref(), Some("committed"));
        assert_eq!(rooted_originals(&fx).len(), 1);
        recover(&fx);
        assert_published(&fx);
    }

    fn journal_state(fx: &Fixture) -> Option<String> {
        let bytes = fs::read(journal_path(fx)).ok()?;
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        value["state"].as_str().map(str::to_string)
    }

    fn fail_at(at: FaultPoint) -> impl FnMut(FaultPoint) -> Fault + 'static {
        move |point| {
            if point == at {
                Fault::Fail
            } else {
                Fault::Continue
            }
        }
    }

    /// Recovery with `hook` installed, returning its result.
    fn recover_with(
        fx: &Fixture,
        hook: impl FnMut(FaultPoint) -> Fault + 'static,
    ) -> io::Result<Vec<Restored>> {
        let activity = fx.store.activity(ActivityMode::Shared).unwrap();
        set_hook(hook);
        let result = recover_project(&fx.store, &activity, &fx.project);
        clear_hook();
        result
    }

    /// A publication that fails at the swap of the lock file (target 1),
    /// with `then` answering every later fault point.
    fn fail_then(then: impl Fn(FaultPoint) -> Fault + 'static) -> impl FnMut(FaultPoint) -> Fault {
        move |point| {
            if point == FaultPoint::Marked(1) {
                Fault::Fail
            } else {
                then(point)
            }
        }
    }

    /// `tog gc` collecting an unrooted originals object.
    fn collect_originals(fx: &Fixture, id: &str) {
        store::remove_tree(&fx.store.object_path(id)).unwrap();
        let _ = fs::remove_file(fx.store.root.join("meta").join(format!("{id}.json")));
        assert!(fx.store.published_identity(id).unwrap().is_none());
    }

    fn journal_originals(fx: &Fixture) -> String {
        let value: serde_json::Value =
            serde_json::from_slice(&fs::read(journal_path(fx)).unwrap()).unwrap();
        value["originals"].as_str().unwrap().to_string()
    }

    /// Releasing the originals fails after commit: the journal survives as
    /// finished with the originals still rooted, so the next recovery
    /// releases them rather than leaving them rooted for good.
    #[test]
    fn a_failed_release_after_commit_is_retried_by_recovery() {
        let fx = fixture("release-fails", true);
        let published = run_door(&fx, |_| {}, fail_at(FaultPoint::Releasing)).unwrap();
        assert!(
            matches!(published, Published::CleanupPending(_)),
            "{published:?}"
        );
        assert_eq!(read(&fx, "package-lock.json").as_deref(), Some(NEW_LOCK));
        assert_eq!(journal_state(&fx).as_deref(), Some("finished"));
        assert_eq!(rooted_originals(&fx).len(), 1);
        // Recovery's own release can fail too; the journal still stays.
        recover_with(&fx, fail_at(FaultPoint::Releasing)).unwrap_err();
        assert_eq!(journal_state(&fx).as_deref(), Some("finished"));
        assert_eq!(rooted_originals(&fx).len(), 1);
        recover(&fx);
        assert_published(&fx);
    }

    /// Killed after the release and before the journal was deleted: the
    /// finished journal is trusted without its originals rooted, even
    /// once `tog gc` has collected them, and recovery deletes it.
    #[test]
    fn a_crash_after_the_release_is_finished_by_recovery() {
        for collected in [false, true] {
            let fx = fixture("released-crash", true);
            let error = run_door(&fx, |_| {}, crash_at(FaultPoint::Released)).unwrap_err();
            assert!(is_crash(&error), "{error}");
            assert_eq!(journal_state(&fx).as_deref(), Some("finished"));
            assert!(rooted_originals(&fx).is_empty());
            if collected {
                collect_originals(&fx, &journal_originals(&fx));
            }
            recover(&fx);
            assert_published(&fx);
            assert!(!fx.project.join(JOURNAL_DIR).exists(), "{collected}");
        }
    }

    /// A finished journal is trusted without rooted originals, but not
    /// blindly: originals of another kind or ecosystem, or a created
    /// directory outside what a transaction creates, are refused and
    /// nothing is touched.
    #[test]
    fn a_forged_finished_journal_is_refused() {
        let fx = fixture("forged-finished", true);
        let _ = run_door(&fx, |_| {}, crash_at(FaultPoint::Released));
        assert_eq!(journal_state(&fx).as_deref(), Some("finished"));
        let good: serde_json::Value =
            serde_json::from_slice(&fs::read(journal_path(&fx)).unwrap()).unwrap();
        let activity = fx.store.activity(ActivityMode::Shared).unwrap();
        crate::kernel::objmeta::register_test_kinds();
        let mut foreign = Vec::new();
        for identity in [
            Identity {
                kind: "test".into(),
                name: "npm".into(),
                version: "1".into(),
                inputs: Default::default(),
            },
            originals_identity("cargo", &"1".repeat(32), &[]),
        ] {
            let staged = fx.store.stage_with_activity(&activity).unwrap();
            fx.store
                .commit_with_activity_and_deps(
                    &activity,
                    &identity,
                    &staged,
                    &[],
                    &ObjectDeps::new(),
                )
                .unwrap();
            foreign.push(identity.object_id());
        }
        drop(activity);
        fs::create_dir_all(fx.project.join("elsewhere")).unwrap();
        let mut cases: Vec<(serde_json::Value, &str)> = Vec::new();
        for id in &foreign {
            let mut journal = good.clone();
            journal["originals"] = id.as_str().into();
            cases.push((journal, "is not a npm originals object"));
        }
        let mut journal = good.clone();
        journal["created_dirs"] = serde_json::json!(["elsewhere"]);
        cases.push((journal, "as a directory it created"));
        for (journal, expected) in cases {
            fs::write(journal_path(&fx), serde_json::to_vec(&journal).unwrap()).unwrap();
            let error = recover_err(&fx).to_string();
            assert!(error.contains("nothing was changed"), "{error}");
            assert!(error.contains(expected), "{error}");
            assert!(journal_path(&fx).is_file());
            assert!(fx.project.join("elsewhere").is_dir());
        }
        fs::write(journal_path(&fx), serde_json::to_vec(&good).unwrap()).unwrap();
        recover(&fx);
        assert_published(&fx);
    }

    /// A finished or held journal whose originals are not in the store
    /// recovering it is consumed only by the store that wrote it: another
    /// store refuses it (its originals are still rooted in the first), and
    /// the first then finishes it. A held journal written before journals
    /// named their store is still trusted.
    #[test]
    fn another_stores_finished_or_held_journal_is_refused() {
        let fx = fixture("finished-two-stores", true);
        let _ = run_door(&fx, |_| {}, crash_at(FaultPoint::Released));
        assert_eq!(journal_state(&fx).as_deref(), Some("finished"));
        let other = fixture("finished-two-stores-other", false);
        let elsewhere = Fixture {
            store: other.store.clone(),
            project: fx.project.clone(),
            _temp: other._temp,
        };
        for state in ["finished", "held"] {
            edit_journal(&fx, |journal| journal["state"] = state.into());
            let error = recover_err(&elsewhere).to_string();
            assert!(error.contains("not in this store"), "{state}: {error}");
            assert!(error.contains("TOG_STORE"), "{state}: {error}");
            assert!(journal_path(&fx).is_file(), "{state}");
        }
        // A finished journal naming no store is refused too.
        edit_journal(&fx, |journal| {
            journal["state"] = "finished".into();
            journal.as_object_mut().unwrap().remove("store");
        });
        assert!(recover_err(&elsewhere)
            .to_string()
            .contains("not in this store"));
        // An old held journal, which names no store, is trusted as before.
        edit_journal(&fx, |journal| journal["state"] = "held".into());
        recover(&elsewhere);
        assert!(!has_pending_journal(&fx.project));
    }

    /// The same two failures on the rollback path: the undone project
    /// stays undone, and recovery releases and deletes the journal.
    #[test]
    fn a_failed_or_interrupted_release_after_an_undo_is_finished_by_recovery() {
        let fx = fixture("undo-release-fails", true);
        let error = run_door(
            &fx,
            |_| {},
            fail_then(|point| {
                if point == FaultPoint::Releasing {
                    Fault::Fail
                } else {
                    Fault::Continue
                }
            }),
        )
        .unwrap_err();
        let text = error.to_string();
        assert!(text.contains("injected failure at Marked(1)"), "{text}");
        assert!(text.contains("cleaning up after it failed"), "{text}");
        assert_eq!(journal_state(&fx).as_deref(), Some("finished"));
        assert_eq!(rooted_originals(&fx).len(), 1);
        assert_eq!(read(&fx, "package.json").as_deref(), Some(OLD_MANIFEST));
        recover(&fx);
        assert_original(&fx, Some(OLD_RECEIPT));

        let fx = fixture("undo-released-crash", true);
        let error = run_door(
            &fx,
            |_| {},
            fail_then(|point| {
                if point == FaultPoint::Released {
                    Fault::Crash
                } else {
                    Fault::Continue
                }
            }),
        )
        .unwrap_err();
        assert!(is_crash(&error), "{error}");
        assert_eq!(journal_state(&fx).as_deref(), Some("finished"));
        assert!(rooted_originals(&fx).is_empty());
        recover(&fx);
        assert_original(&fx, Some(OLD_RECEIPT));
    }

    /// Recovery of a crashed publication whose own release fails keeps a
    /// finished journal (never an untrusted one), and the next finishes.
    #[test]
    fn recovery_whose_release_fails_or_crashes_is_finished_next_time() {
        for (point, committed) in [
            (FaultPoint::Committed, true),
            (FaultPoint::Marked(1), false),
        ] {
            for fault in [Fault::Fail, Fault::Crash] {
                let fx = fixture("recovery-release", true);
                let _ = run_door(&fx, |_| {}, crash_at(point));
                let at = if fault == Fault::Fail {
                    FaultPoint::Releasing
                } else {
                    FaultPoint::Released
                };
                recover_with(&fx, move |p| if p == at { fault } else { Fault::Continue })
                    .unwrap_err();
                assert_eq!(
                    journal_state(&fx).as_deref(),
                    Some("finished"),
                    "{point:?} {fault:?}"
                );
                recover(&fx);
                if committed {
                    assert_published(&fx);
                } else {
                    assert_original(&fx, Some(OLD_RECEIPT));
                }
            }
        }
    }

    /// Abandoning a hold whose release fails, or is interrupted after it,
    /// leaves the held journal, which the next recovery finishes.
    #[test]
    fn a_failed_or_interrupted_release_of_a_hold_is_finished_by_recovery() {
        for (at, fault) in [
            (FaultPoint::Releasing, Fault::Fail),
            (FaultPoint::Released, Fault::Crash),
        ] {
            let fx = fixture("hold-release", true);
            let activity = fx.store.activity(ActivityMode::Shared).unwrap();
            let declared = declared();
            let tx = Transaction::hold(
                &fx.store,
                &activity,
                ProjectRoot::open(&fx.project).unwrap(),
                &HoldSpec {
                    ecosystem: "npm",
                    outputs: &declared,
                    receipt: true,
                },
            )
            .unwrap();
            set_hook(move |p| if p == at { fault } else { Fault::Continue });
            let result = tx.abandon();
            clear_hook();
            result.unwrap_err();
            assert_eq!(journal_state(&fx).as_deref(), Some("held"), "{at:?}");
            let rooted = if fault == Fault::Fail { 1 } else { 0 };
            assert_eq!(rooted_originals(&fx).len(), rooted, "{at:?}");
            drop(activity);
            recover(&fx);
            assert_original(&fx, Some(OLD_RECEIPT));
            assert!(!fx.project.join(JOURNAL_DIR).exists(), "{at:?}");
        }
    }

    /// A process killed while the tool ran (after hold, before publish)
    /// leaves a `held` journal; recovery releases the originals it names.
    #[test]
    fn originals_held_by_a_killed_run_are_released_by_recovery() {
        let fx = fixture("killed-run", true);
        let activity = fx.store.activity(ActivityMode::Shared).unwrap();
        let declared = declared();
        let tx = Transaction::hold(
            &fx.store,
            &activity,
            ProjectRoot::open(&fx.project).unwrap(),
            &HoldSpec {
                ecosystem: "npm",
                outputs: &declared,
                receipt: true,
            },
        )
        .unwrap();
        // What a killed process leaves: nothing released, locks closed.
        let mut tx = tx;
        tx.finished = true;
        drop(tx);
        assert_eq!(rooted_originals(&fx).len(), 1);
        assert!(has_pending_journal(&fx.project));
        drop(activity);
        recover(&fx);
        assert_original(&fx, Some(OLD_RECEIPT));
        assert!(!fx.project.join(JOURNAL_DIR).exists());
    }

    /// The project directory's own lock is held from hold to publish, so a
    /// tog using another store cannot recover (or publish) meanwhile.
    #[test]
    fn a_transaction_holds_the_project_directory_lock() {
        let fx = fixture("dir-lock", true);
        let activity = fx.store.activity(ActivityMode::Shared).unwrap();
        let declared = declared();
        let tx = Transaction::hold(
            &fx.store,
            &activity,
            ProjectRoot::open(&fx.project).unwrap(),
            &HoldSpec {
                ecosystem: "npm",
                outputs: &declared,
                receipt: true,
            },
        )
        .unwrap();
        let dir = fs::File::open(&fx.project).unwrap();
        assert!(
            dir.try_lock().is_err(),
            "the project directory is not locked"
        );
        tx.abandon().unwrap();
        assert!(dir.try_lock().is_ok());
    }

    /// A run with another store finds this store's journal and refuses it,
    /// rather than undoing a publication it knows nothing about.
    #[test]
    fn recovery_with_another_store_refuses_the_journal() {
        let fx = fixture("two-stores", true);
        let _ = run_door(&fx, |_| {}, crash_at(FaultPoint::Marked(1)));
        let other = fixture("two-stores-other", false);
        let elsewhere = Fixture {
            store: other.store.clone(),
            project: fx.project.clone(),
            _temp: other._temp,
        };
        let error = recover_err(&elsewhere);
        assert!(error.to_string().contains("not in this store"), "{error}");
        assert_eq!(read(&fx, "package-lock.json").as_deref(), Some(NEW_LOCK));
        recover(&fx);
        assert_original(&fx, Some(OLD_RECEIPT));
    }

    /// A file the publication creates gets the ordinary file mode, not the
    /// bits the tool left on it.
    #[test]
    fn a_created_output_gets_the_ordinary_file_mode() {
        use std::os::unix::fs::PermissionsExt;
        let fx = fixture("created-mode", true);
        run_door(&fx, |_| {}, |_| Fault::Continue).unwrap();
        let mode = fs::metadata(fx.project.join("package-lock.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, new_file_mode());
        assert_eq!(mode & 0o111, 0);
    }
}

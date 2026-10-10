//! `status`, `ls`, `doctor`: read-only views over the project's closures and
//! the store. Nothing here realizes, resolves, or touches the network;
//! `doctor` is the only function that opens the store, and it only reads.

use std::fs;
use std::io::{self, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

pub use crate::comforter::status::{sha256_file, string, State};
use crate::kernel::activity::StoreActivity;
use crate::kernel::fsroot::ProjectRoot;
use crate::kernel::platform::Platform;
use crate::kernel::policy::{Exception, OptionalGroupSkipped};
use crate::kernel::sandbox;
use crate::kernel::store::{MetaFile, Store};
use crate::kernel::toolchain::input;
use crate::kernel::toolchain::lock::{self as toolchain_lock, ToolchainLock, LOCK_PATH};
use crate::tailors;

use crate::comforter::records;
pub use crate::comforter::records::{
    exceptions, open_project, optional_groups_skipped, recorded_exceptions, resolution_exceptions,
    ClosureFile, ExceptionList,
};
pub use crate::tailors::PackageRow;

/// Display order: the tailor registry's.
pub fn ecosystems() -> Vec<&'static str> {
    tailors::registry()
        .iter()
        .map(|tailor| tailor.id())
        .collect()
}

/// The ecosystems whose inputs are present in `dir` itself (the same tests
/// `sync` uses to decide what to realize).
pub fn detected(dir: &Path) -> io::Result<Vec<&'static str>> {
    Ok(tailors::detected(dir)?
        .into_iter()
        .map(|tailor| tailor.id())
        .collect())
}

/// Every closure written here, in display order. Foreign-platform closures
/// are included (the caller decides what they mean), unlike
/// `project::read_closure`, which refuses them.
pub fn closures(dir: &Path) -> io::Result<Vec<ClosureFile>> {
    match open_project(dir)? {
        Some(project) => closures_in(&project),
        None => Ok(Vec::new()),
    }
}

/// `closures` for a project the command holds
/// (`comforter::records::closure_files`), in display order.
pub fn closures_in(project: &ProjectRoot) -> io::Result<Vec<ClosureFile>> {
    let mut out = records::closure_files(project)?;
    out.sort_by_key(|closure| rank(&closure.ecosystem));
    Ok(out)
}

fn rank(ecosystem: &str) -> usize {
    let order = ecosystems();
    order
        .iter()
        .position(|name| *name == ecosystem)
        .unwrap_or(order.len())
}

// ---------------------------------------------------------------------------
// ls

#[derive(Debug, Clone)]
pub struct Listing {
    pub ecosystem: String,
    pub platform: Option<String>,
    pub toolchain: Vec<(String, String)>,
    pub packages: Vec<PackageRow>,
}

pub fn listing(closure: &ClosureFile) -> Listing {
    let mut listed = tailors::for_closure(&closure.ecosystem)
        .map(|tailor| tailor.listing(&closure.ecosystem, &closure.body))
        .unwrap_or_default();
    listed.toolchain.retain(|(_, version)| !version.is_empty());
    listed
        .packages
        .sort_by(|a, b| a.name.cmp(&b.name).then(a.version.cmp(&b.version)));
    Listing {
        ecosystem: closure.ecosystem.clone(),
        platform: closure.platform.clone(),
        toolchain: listed.toolchain,
        packages: listed.packages,
    }
}

/// The `ls` output for stdout. `Err(NotFound)` when nothing is synced.
pub fn ls(dir: &Path, filter: Option<&str>, json: bool, verbose: bool) -> io::Result<String> {
    let listings: Vec<Listing> = closures(dir)?
        .iter()
        .filter(|closure| filter.is_none_or(|name| closure.ecosystem == name))
        .map(listing)
        .collect();
    if listings.is_empty() {
        let message = match filter {
            Some(name) if !closures(dir)?.is_empty() => {
                format!("no {name} closure here; 'tog ls' lists what is synced")
            }
            _ => "nothing synced here; run 'tog' first".to_string(),
        };
        return Err(io::Error::new(io::ErrorKind::NotFound, message));
    }
    if json {
        let value = json!({
            "project": dir,
            "ecosystems": listings.iter().map(|listing| json!({
                "ecosystem": listing.ecosystem,
                "platform": listing.platform,
                "toolchain": listing.toolchain.iter().map(|(name, version)| json!({
                    "name": name, "version": version
                })).collect::<Vec<_>>(),
                "packages": listing.packages.iter().map(|package| json!({
                    "name": package.name,
                    "version": package.version,
                    "detail": package.detail,
                })).collect::<Vec<_>>(),
            })).collect::<Vec<_>>(),
        });
        return Ok(serde_json::to_string_pretty(&value)? + "\n");
    }
    let mut out = String::new();
    for (index, listing) in listings.iter().enumerate() {
        if index > 0 {
            out.push('\n');
        }
        let toolchain = listing
            .toolchain
            .iter()
            .map(|(name, version)| format!("{name} {version}"))
            .collect::<Vec<_>>()
            .join(", ");
        out.push_str(&format!(
            "{}  ({}; {} package{})\n",
            listing.ecosystem,
            toolchain,
            listing.packages.len(),
            if listing.packages.len() == 1 { "" } else { "s" }
        ));
        let width = listing
            .packages
            .iter()
            .map(|package| package.name.len())
            .max()
            .unwrap_or(0);
        for package in &listing.packages {
            if verbose && !package.detail.is_empty() {
                out.push_str(&format!(
                    "  {:width$}  {}  {}\n",
                    package.name, package.version, package.detail
                ));
            } else {
                out.push_str(&format!("  {:width$}  {}\n", package.name, package.version));
            }
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// status

#[derive(Debug, Clone)]
pub struct EcosystemStatus {
    pub ecosystem: String,
    pub state: State,
    /// Toolchain and package count, for the synced line.
    pub summary: String,
    /// What the sync that wrote this closure allowed and could not vouch
    /// for, as recorded (`inspect::exceptions`). Shown under the row and
    /// in `--json`; never part of the state, which is about freshness.
    pub exceptions: Vec<Exception>,
    /// Why the exception list could not be read, when it could not. An
    /// empty `exceptions` beside this is "unknown", not "none recorded":
    /// the row says so whatever its state is.
    pub exceptions_error: Option<String>,
    /// Optional groups the sync left out because nobody requested them.
    /// Informational, never an exception (#71).
    pub optional_groups_skipped: Vec<OptionalGroupSkipped>,
    /// Why that list could not be read, when it could not: reported the
    /// way `exceptions_error` is, so both signed lists behave alike.
    pub optional_groups_skipped_error: Option<String>,
}

impl EcosystemStatus {
    /// Only a closure this binary compared against the files on disk is
    /// synced. `Unchecked` is the answer "this could not be verified", and
    /// a CI gate that reads it as a pass passes anything old enough.
    pub fn is_synced(&self) -> bool {
        matches!(self.state, State::Synced)
    }

    /// The state word `--json` reports and the summary line counts.
    pub fn word(&self) -> &'static str {
        match self.state {
            State::Synced => "synced",
            State::NotSynced => "not-synced",
            State::Changed(_) => "changed",
            State::ProjectionMissing(_) => "projection-missing",
            State::ForeignPlatform(_) => "foreign-platform",
            State::Unchecked(_) => "unchecked",
        }
    }
}

/// `tog status` for `dir`: the project is opened once and every read the
/// report makes goes through that descriptor.
pub fn status(platform: Platform, dir: &Path) -> io::Result<Vec<EcosystemStatus>> {
    match open_project(dir)? {
        Some(project) => status_in(platform, &project),
        None => Ok(Vec::new()),
    }
}

pub fn status_in(platform: Platform, project: &ProjectRoot) -> io::Result<Vec<EcosystemStatus>> {
    let present: Vec<&str> = tailors::detected_in(project)?
        .into_iter()
        .map(|tailor| tailor.id())
        .collect();
    let closures = closures_in(project)?;
    let mut rows = Vec::new();
    for ecosystem in present {
        let Some(closure) = closures
            .iter()
            .find(|closure| closure.ecosystem == ecosystem)
        else {
            rows.push(EcosystemStatus {
                ecosystem: ecosystem.into(),
                state: State::NotSynced,
                summary: String::new(),
                exceptions: Vec::new(),
                exceptions_error: None,
                optional_groups_skipped: Vec::new(),
                optional_groups_skipped_error: None,
            });
            continue;
        };
        let mut state = locked_closure_state(platform, project, closure)?;
        // A record whose exception list cannot be read is this row's
        // finding, not the report's: the other ecosystems still report,
        // and a state that already names a fix keeps it. The error is
        // carried beside the state either way, so an empty list is never
        // read as "no exceptions".
        let (exceptions, exceptions_error) = match exceptions(closure) {
            Ok(list) => (list.exceptions, None),
            Err(error) => {
                let error = error.to_string();
                if state == State::Synced {
                    state = State::Unchecked(error.clone());
                }
                (Vec::new(), Some(error))
            }
        };
        let (optional_groups_skipped, optional_groups_skipped_error) =
            match optional_groups_skipped(closure) {
                Ok(groups) => (groups, None),
                Err(error) => {
                    let error = error.to_string();
                    if state == State::Synced {
                        state = State::Unchecked(error.clone());
                    }
                    (Vec::new(), Some(error))
                }
            };
        rows.push(EcosystemStatus {
            ecosystem: ecosystem.into(),
            state,
            summary: summary(closure),
            exceptions,
            exceptions_error,
            optional_groups_skipped,
            optional_groups_skipped_error,
        });
    }
    Ok(rows)
}

/// The state of one closure file as `tog status` reports it and `tog audit`
/// judges it: the record's own `closure_state`, combined with what the
/// committed `tog-toolchain.toml` says about the ecosystem that wrote it.
/// One function, so the gate can never pass a record that `status` calls
/// out of step with the lock.
///
/// A lock verdict that a writable sync would refuse (stale rows, no
/// section) is reported first: the closure may also say a source changed,
/// but "run 'tog'" would only reach the refusal, and the lock's line names
/// the verb that moves it. Otherwise the closure state decides, and only a
/// `Synced` closure is downgraded to what the lock has to add.
pub fn locked_closure_state(
    platform: Platform,
    project: &ProjectRoot,
    closure: &ClosureFile,
) -> io::Result<State> {
    let mut state = closure_state(platform, project, closure)?;
    match toolchain_lock_state(project, &closure.ecosystem, &closure.body)? {
        Some(LockVerdict {
            state: verdict,
            refuses_sync: true,
        }) => state = verdict,
        Some(LockVerdict { state: verdict, .. }) if state == State::Synced => state = verdict,
        _ => {}
    }
    if state == State::Synced {
        if let Some(verdict) = helper_state(project, &closure.ecosystem, &closure.body)? {
            state = verdict;
        }
    }
    if state == State::Synced {
        if let Some(verdict) = resolution_state(project, closure) {
            state = verdict;
        }
    }
    Ok(state)
}

/// Whether the resolution record `closure` joined still describes the
/// files in `dir`: `None` when it does (or there is no record), else
/// `Changed` naming each file whose digest differs from the record's
/// signed one, plus any resolution file of the ecosystem that exists now
/// but that the record never named. The toolchain-input rows see only
/// go.mod's `go` and `toolchain` directives and go.sum, so a dependency
/// added to go.mod alone shows here. A record whose digest maps do not
/// parse, or a file that cannot be read to compare, is `Unchecked` for
/// this closure alone, never an error for the whole command.
pub fn resolution_state(project: &ProjectRoot, closure: &ClosureFile) -> Option<State> {
    let resolution = closure.body.get("resolution")?;
    match resolution_changes(project, &closure.ecosystem, resolution) {
        Ok(changed) if changed.is_empty() => None,
        Ok(changed) => Some(State::Changed(changed)),
        Err(why) => Some(State::Unchecked(format!(
            "the resolution record cannot be compared with the lock: {why}; run 'tog'"
        ))),
    }
}

fn resolution_changes(
    project: &ProjectRoot,
    ecosystem: &str,
    resolution: &Value,
) -> Result<Vec<String>, String> {
    use crate::kernel::resolve::record;
    use std::collections::{BTreeMap, BTreeSet};
    let digests = |field: &str| -> Result<BTreeMap<String, String>, String> {
        let value = resolution
            .get(field)
            .ok_or_else(|| format!("malformed resolution record: no {field} map"))?;
        let map: BTreeMap<String, String> = serde_json::from_value(value.clone())
            .map_err(|error| format!("malformed resolution record: {field}: {error}"))?;
        for (path, digest) in &map {
            if record::record_path(Path::new(path)).as_deref() != Some(path.as_str()) {
                return Err(format!(
                    "malformed resolution record: {field} names {path:?}"
                ));
            }
            if !record::is_sha256_hex(digest) {
                return Err(format!(
                    "malformed resolution record: {field} digest for {path} is not a sha256"
                ));
            }
        }
        Ok(map)
    };
    let mut named = digests("outputs")?;
    named.extend(digests("inputs")?);
    let mut changed = BTreeSet::new();
    for (path, digest) in &named {
        let current = if project.is_input_file(Path::new(path)) {
            project
                .read_input(Path::new(path))
                .map_err(|error| format!("read {path}: {error}"))?
                .map(|bytes| record::sha256_hex(&bytes))
        } else {
            None
        };
        if current.as_deref() != Some(digest.as_str()) {
            changed.insert(path.clone());
        }
    }
    let files = match tailors::by_id(ecosystem) {
        Some(tailor) => {
            tailors::resolution_files(tailor, project).map_err(|error| error.to_string())?
        }
        None => None,
    };
    if let Some(files) = files {
        let mut listed = files.outputs;
        listed.extend(files.inputs);
        let present = record::file_digests(project, &listed).map_err(|error| error.to_string())?;
        for path in present.into_keys() {
            if !named.contains_key(&path) {
                changed.insert(path);
            }
        }
    }
    Ok(changed.into_iter().collect())
}

/// Whether the helper toolchains a closure recorded (`Tailor::helpers`,
/// e.g. node-gyp's Python) are still the ones a sync would decide now.
/// The decision is `tailors::helper_selections` over the project as it
/// stands: a helper ecosystem the project has is its lock section, any
/// other the tailor's default. Removing the Python manifest from a
/// Python-and-Node project therefore moves Node's gyp Python from the
/// locked one to the shipped default, and Node is out of step until it
/// syncs.
///
/// A helper ecosystem the project has but the lock does not cover is
/// skipped here: that ecosystem's own row already names the lock verb. A
/// closure with no recorded decision predates this record and was built on
/// the shipped helpers, which is what `null` means.
fn helper_state(project: &ProjectRoot, ecosystem: &str, body: &Value) -> io::Result<Option<State>> {
    let Some(tailor) = tailors::by_id(ecosystem) else {
        return Ok(None);
    };
    if tailor.helpers().is_empty() {
        return Ok(None);
    }
    let present = tailors::detected_in(project)?;
    let lock = ToolchainLock::read_via(project)?;
    let mut changed = Vec::new();
    for helper in tailor.helpers() {
        let has_helper = present
            .iter()
            .any(|present| present.lock_ecosystem() == *helper);
        let current = if has_helper {
            match lock.as_ref().and_then(|lock| lock.ecosystem(helper)) {
                Some(section) => Some(section.bundle_id().to_string()),
                None => continue,
            }
        } else {
            tailor
                .default_helper(helper)?
                .map(|selected| selected.bundle_id())
        };
        let recorded = body["toolchain"]["helpers"][*helper]
            .as_str()
            .map(str::to_string);
        if recorded != current {
            changed.push(format!("the {helper} toolchain {ecosystem} builds with"));
        }
    }
    Ok((!changed.is_empty()).then_some(State::Changed(changed)))
}

/// Whether every entry of a `Changed` state is a toolchain-lock finding.
/// Such a line already carries its own next step, and it is not always the
/// bare `tog`, so `status` and `audit` print it as written rather than
/// wrapping it in the dependency-input sentence.
pub fn only_lock_findings(files: &[String]) -> bool {
    !files.is_empty() && files.iter().all(|file| file.starts_with(LOCK_PATH))
}

/// What the toolchain lock adds to a status row, and whether a plain
/// sync would stop at it: a missing lock is created by the next
/// writable sync and a changed bundle is re-projected by it, but stale
/// rows and a missing section are only moved by `tog update --toolchain`.
struct LockVerdict {
    state: State,
    refuses_sync: bool,
}

impl LockVerdict {
    fn changed(rows: Vec<String>, refuses_sync: bool) -> Option<Self> {
        Some(Self {
            state: State::Changed(rows),
            refuses_sync,
        })
    }
}

/// What the committed `tog-toolchain.toml` says about one detected
/// ecosystem, if anything: `None` means the lock agrees with both the
/// project and the closure.
///
/// The comparison is the same one a sync would refuse over — re-derive
/// every consulted row and compare presence and value, never the source
/// file's digest alone — so `tog status` predicts the next sync rather than
/// having a second opinion about staleness.
fn toolchain_lock_state(
    project: &ProjectRoot,
    ecosystem: &str,
    body: &Value,
) -> io::Result<Option<LockVerdict>> {
    let Some(tailor) = tailors::by_id(ecosystem) else {
        return Ok(None);
    };
    let lock_ecosystem = tailor.lock_ecosystem();
    let Some(lock) = ToolchainLock::read_via(project)? else {
        return Ok(LockVerdict::changed(
            vec![format!("{LOCK_PATH} (missing; run 'tog' to create it)")],
            false,
        ));
    };
    let Some(section) = lock.ecosystem(lock_ecosystem) else {
        return Ok(LockVerdict::changed(
            vec![format!(
                "{LOCK_PATH} (no [toolchain.{lock_ecosystem}] section; \
                 run 'tog update --toolchain {lock_ecosystem}')"
            )],
            true,
        ));
    };
    // A toolchain file that does not parse is never the lock's answer: it is
    // stale, named, and a sync refuses it the same way.
    let current = match input::discover(project, lock_ecosystem) {
        Ok(current) => current,
        Err(error) if error.kind() == io::ErrorKind::InvalidData => {
            return Ok(LockVerdict::changed(
                vec![format!("{LOCK_PATH} stale: {error}")],
                true,
            ));
        }
        Err(error) => return Err(error),
    };
    let stale = toolchain_lock::stale_rows(&section.inputs(), &current);
    if !stale.is_empty() {
        return Ok(LockVerdict::changed(
            stale
                .iter()
                .map(|row| {
                    format!(
                        "{LOCK_PATH} stale: {row}; run 'tog update --toolchain {lock_ecosystem}'"
                    )
                })
                .collect(),
            true,
        ));
    }
    // Which bundle this projection was actually built from. A closure that
    // never recorded one cannot be compared at all, which is the same
    // answer every other unrecorded field gets.
    let Some(recorded) = body["toolchain"]["bundle_id"].as_str() else {
        return Ok(Some(LockVerdict {
            state: State::Unchecked("toolchain not recorded by this sync; run 'tog' once".into()),
            refuses_sync: false,
        }));
    };
    if recorded != section.bundle_id() {
        return Ok(LockVerdict::changed(
            vec![format!(
                "{LOCK_PATH} (toolchain changed since the last sync; run 'tog')"
            )],
            false,
        ));
    }
    Ok(None)
}

/// Toolchain and package count, for the synced line.
pub fn summary(closure: &ClosureFile) -> String {
    let listing = listing(closure);
    format!(
        "{}; {} package{}",
        listing
            .toolchain
            .iter()
            .map(|(name, version)| format!("{name} {version}"))
            .collect::<Vec<_>>()
            .join(", "),
        listing.packages.len(),
        if listing.packages.len() == 1 { "" } else { "s" }
    )
}

pub fn closure_state(
    platform: Platform,
    project: &ProjectRoot,
    closure: &ClosureFile,
) -> io::Result<State> {
    if let Some(recorded) = &closure.platform {
        if recorded != platform.triple() {
            return Ok(State::ForeignPlatform(recorded.clone()));
        }
    }
    match tailors::for_closure(&closure.ecosystem) {
        Some(tailor) => tailor.closure_state(platform, project, &closure.ecosystem, &closure.body),
        None => Ok(State::Unchecked("unknown ecosystem".into())),
    }
}

pub fn render_status(dir: &Path, rows: &[EcosystemStatus], json: bool) -> io::Result<String> {
    if json {
        let value = json!({
            "project": dir,
            "synced": rows.iter().all(EcosystemStatus::is_synced),
            "ecosystems": rows.iter().map(|row| {
                let detail: Value = match &row.state {
                    State::Synced | State::NotSynced => Value::Null,
                    State::Changed(files) => json!(files),
                    State::ProjectionMissing(what) => json!(what),
                    State::ForeignPlatform(platform) => json!(platform),
                    State::Unchecked(why) => json!(why),
                };
                json!({
                    "ecosystem": row.ecosystem,
                    "state": row.word(),
                    "detail": detail,
                    "summary": row.summary,
                    "exceptions": row.exceptions,
                    "exceptions_error": row.exceptions_error,
                    "optional_groups_skipped": row.optional_groups_skipped,
                    "optional_groups_skipped_error": row.optional_groups_skipped_error,
                })
            }).collect::<Vec<_>>(),
        });
        return Ok(serde_json::to_string_pretty(&value)? + "\n");
    }
    let width = rows
        .iter()
        .map(|row| row.ecosystem.len())
        .max()
        .unwrap_or(0);
    let mut out = String::new();
    for row in rows {
        let line = match &row.state {
            State::Synced => format!("synced      ({})", row.summary),
            State::NotSynced => "not synced  run 'tog'".to_string(),
            State::Changed(files) if only_lock_findings(files) => {
                format!("changed     {}", files.join(", "))
            }
            State::Changed(files) => format!(
                "changed     {} since the last sync; run 'tog'",
                files.join(", ")
            ),
            State::ProjectionMissing(what) => {
                format!("missing     {what} is not the synced projection; run 'tog'")
            }
            State::ForeignPlatform(platform) => {
                format!("elsewhere   last synced on {platform}, not on this host; run 'tog'")
            }
            State::Unchecked(why) => format!("unchecked   {why}"),
        };
        out.push_str(&format!("{:width$}  {line}\n", row.ecosystem));
        for exception in &row.exceptions {
            out.push_str(&printable(&format!(
                "{:width$}    exception   {}  {}",
                "", exception.kind, exception.subject
            )));
            out.push('\n');
        }
        for group in &row.optional_groups_skipped {
            let count = match group.requirements.len() {
                0 => String::new(),
                1 => " (1 requirement)".to_string(),
                n => format!(" ({n} requirements)"),
            };
            out.push_str(&printable(&format!(
                "{:width$}    optional    {}{count} not installed: {}",
                "", group.group, group.detail
            )));
            out.push('\n');
        }
        // An unchecked row already printed this reason as its own.
        for (label, error) in [
            ("exception", &row.exceptions_error),
            ("optional ", &row.optional_groups_skipped_error),
        ] {
            let Some(error) = error else { continue };
            if !matches!(&row.state, State::Unchecked(why) if why == error) {
                out.push_str(&printable(&format!(
                    "{:width$}    {label}   unreadable  {error}",
                    ""
                )));
                out.push('\n');
            }
        }
    }
    out.push_str(&verdict(rows));
    Ok(out)
}

/// A status line as the text report prints it: control characters (an
/// exception subject comes from the record) are escaped so a record cannot
/// rewrite the terminal lines above it. Ordinary text prints unchanged.
fn printable(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c.is_control() {
                c.escape_debug().to_string()
            } else {
                c.to_string()
            }
        })
        .collect()
}

/// The last line (or three) of `tog status`: what the rows add up to, and
/// what the words that are not `synced` mean. A reader who scrolled past
/// the rows should not have to count them, and a state the binary could not
/// check has to say so where the verdict is read.
fn verdict(rows: &[EcosystemStatus]) -> String {
    let synced = rows.iter().filter(|row| row.is_synced()).count();
    if synced == rows.len() {
        return format!(
            "\n{synced} of {} synced.\n{}",
            rows.len(),
            exceptions_line(rows)
        );
    }
    let mut counts: Vec<(&str, usize)> = Vec::new();
    for row in rows.iter().filter(|row| !row.is_synced()) {
        match counts.iter_mut().find(|(word, _)| *word == row.word()) {
            Some((_, count)) => *count += 1,
            None => counts.push((row.word(), 1)),
        }
    }
    let listed = counts
        .iter()
        .map(|(word, count)| format!("{count} {word}"))
        .collect::<Vec<_>>()
        .join(", ");
    let mut out = format!("\n{synced} of {} synced; {listed}.\n", rows.len());
    if rows.iter().any(|row| row.word() == "unchecked") {
        out.push_str(
            "unchecked: this closure could not be compared (the row says why), so it\n\
             is not a pass; run 'tog' once to rewrite it.\n",
        );
    }
    if rows.iter().any(|row| row.word() == "foreign-platform") {
        out.push_str(
            "elsewhere: the closure was written on another platform and says nothing\n\
             about this host.\n",
        );
    }
    out.push_str("Exit status is 0 only when every ecosystem is synced.\n");
    out.push_str(&exceptions_line(rows));
    out
}

/// After the verdict: how many exceptions the rows listed, and the one
/// command that judges them. An exception is not a failure here, so the
/// line is absent when there is none.
fn exceptions_line(rows: &[EcosystemStatus]) -> String {
    let total: usize = rows.iter().map(|row| row.exceptions.len()).sum();
    if total == 0 {
        return String::new();
    }
    format!(
        "{total} policy exception(s) recorded: what a sync allowed that it cannot vouch for;\n\
         'tog audit' says whether your policy permits them.\n"
    )
}

// ---------------------------------------------------------------------------
// doctor

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Ok,
    Warn,
    Fail,
}

#[derive(Debug, Clone)]
pub struct Check {
    pub name: &'static str,
    pub level: Level,
    pub detail: String,
}

fn check(name: &'static str, level: Level, detail: impl Into<String>) -> Check {
    Check {
        name,
        level,
        detail: detail.into(),
    }
}

fn on_path(program: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(program))
        .find(|candidate| candidate.is_file())
}

fn free_bytes(path: &Path) -> io::Result<u64> {
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))?;
    // SAFETY: statvfs writes into a zeroed struct of the right type.
    unsafe {
        let mut stats: libc::statvfs = std::mem::zeroed();
        if libc::statvfs(c_path.as_ptr(), &mut stats) != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(stats.f_bavail as u64 * stats.f_frsize as u64)
    }
}

/// Realized toolchains, from the store's metadata files only.
/// The toolchains the store holds, by its object records. Each record is
/// opened from held descriptors and only when it is a regular file: a FIFO
/// or a symlink left under `meta/` is skipped, never opened by its path,
/// where a FIFO would block the report for good.
fn realized_toolchains(store: &Store) -> io::Result<Vec<String>> {
    let mut found = Vec::new();
    // Listed and read through one held `meta/`, so a `meta/` renamed or
    // replaced meanwhile cannot mix one directory's names with another's
    // records.
    let Some(meta) = store.open_object_meta_dir()? else {
        return Ok(found);
    };
    for name in crate::kernel::store::read_dir_names_at(meta.as_raw_fd())? {
        let Some(id) = name.to_str().and_then(|name| name.strip_suffix(".json")) else {
            continue;
        };
        let Ok(MetaFile::File(file)) = crate::kernel::store::open_object_meta_at(&meta, id) else {
            continue;
        };
        let Ok(Ok(value)) = crate::kernel::store::read_meta_json(&file) else {
            continue;
        };
        let identity = &value["identity"];
        let kind = string(&identity["kind"]);
        let toolchain = tailors::registry()
            .iter()
            .any(|tailor| tailor.toolchain_kinds().contains(&kind.as_str()));
        if toolchain {
            let name = string(&identity["name"]);
            let version = string(&identity["version"]);
            found.push(format!(
                "{} {version}",
                if name.is_empty() { kind } else { name }
            ));
        }
    }
    found.sort();
    found.dedup();
    Ok(found)
}

fn count_entries(path: &Path) -> usize {
    fs::read_dir(path)
        .map(|entries| entries.count())
        .unwrap_or(0)
}

/// The host triple, or the failure that makes every platform-dependent
/// probe below unanswerable.
fn host_platform_check(checks: &mut Vec<Check>) -> Option<Platform> {
    match Platform::host() {
        Ok(platform) => {
            checks.push(check("platform", Level::Ok, platform.triple()));
            Some(platform)
        }
        Err(error) => {
            checks.push(check(
                "platform",
                Level::Fail,
                format!("{error}; tog supports macOS arm64 and Linux x86_64"),
            ));
            None
        }
    }
}

/// Prove the store is writable without leaving anything behind.
fn store_writable_check(store: &Store, checks: &mut Vec<Check>) {
    let probe = store.root.join("tmp").join(format!(
        ".doctor-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    // create_new is deliberate: fs::write follows a pre-existing
    // symlink, allowing a hostile or stale probe name to redirect
    // doctor’s write outside the store.
    let writable = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe)
        .and_then(|mut file| {
            file.write_all(b"ok")?;
            drop(file);
            fs::remove_file(&probe)
        });
    match writable {
        Ok(()) => checks.push(check(
            "store",
            Level::Ok,
            format!(
                "{} ({} objects, {} cached artifacts)",
                store.root.display(),
                count_entries(&store.root.join("objects")),
                count_entries(&store.root.join("cache/sha256"))
            ),
        )),
        Err(error) => checks.push(check(
            "store",
            Level::Fail,
            format!(
                "{} is not writable: {error}; set TOG_STORE to a directory you own",
                store.root.display()
            ),
        )),
    }
}

/// Free space under the store; a warning below the headroom a toolchain
/// realization needs.
fn disk_check(store: &Store, checks: &mut Vec<Check>) {
    match free_bytes(&store.root) {
        Ok(bytes) => {
            let gib = bytes as f64 / (1u64 << 30) as f64;
            let level = if bytes < 5 * (1u64 << 30) {
                Level::Warn
            } else {
                Level::Ok
            };
            let hint = if level == Level::Warn {
                "; toolchains and native library sets need several GiB, 'tog gc' frees space"
            } else {
                ""
            };
            checks.push(check(
                "disk",
                level,
                format!("{gib:.1} GiB free under the store{hint}"),
            ));
        }
        Err(error) => checks.push(check("disk", Level::Warn, error.to_string())),
    }
}

/// What this store has already realized, from its records only.
fn toolchains_check(store: &Store, checks: &mut Vec<Check>) {
    match realized_toolchains(store) {
        Ok(toolchains) if toolchains.is_empty() => checks.push(check(
            "toolchains",
            Level::Ok,
            "none realized yet; the first 'tog' downloads what the project needs",
        )),
        Ok(toolchains) => checks.push(check("toolchains", Level::Ok, toolchains.join(", "))),
        Err(error) => checks.push(check("toolchains", Level::Warn, error.to_string())),
    }
}

/// The store as `doctor` was handed it: opened and under a lease, opened
/// with no lease because another job holds it exclusively, or the error
/// that stopped either. The caller decides once, and the lease comes with
/// the store, so nothing here reads a store without one.
pub type DoctorStore<'a> = Result<(&'a Store, Option<&'a StoreActivity>), &'a io::Error>;

/// The store block: opening it is the only thing `doctor` does that could
/// fail for the whole group, so the three probes below hang off the `Ok`.
fn store_checks(store: DoctorStore, checks: &mut Vec<Check>) {
    let (store, activity) = match store {
        Ok((store, Some(activity))) => (store, activity),
        // In use is not broken: a warning, like gc's "cleanup skipped".
        // Nothing in the store is read without the lease.
        Ok((store, None)) => {
            checks.push(check(
                "store",
                Level::Warn,
                format!(
                    "a Tog job is using the store at {}; its checks were skipped, run 'tog \
                     doctor' again when the job finishes",
                    store.root.display()
                ),
            ));
            return;
        }
        Err(error) => {
            checks.push(check("store", Level::Fail, unopened_store_detail(error)));
            return;
        }
    };
    if let Err(error) = store.require_activity(activity, "checking the store") {
        checks.push(check("store", Level::Fail, error.to_string()));
        return;
    }
    store_writable_check(store, checks);
    disk_check(store, checks);
    toolchains_check(store, checks);
}

/// Why the store row fails when the store was not opened. A store written
/// in a format this tog does not read, or whose marker cannot be read, is a
/// refusal: the row gives its reason and keeps the command that is the way
/// out. Any other error names the path, the cause, and TOG_STORE already.
fn unopened_store_detail(error: &io::Error) -> String {
    match crate::kernel::store::refusal_fix(error) {
        Some(fix) => format!("{error}; run '{fix}'"),
        None => format!("cannot {error}"),
    }
}

/// The host C toolchain the native build paths need.
fn c_toolchain_check(platform: Platform, checks: &mut Vec<Check>) {
    let required: &[&str] = match platform {
        Platform::X86_64UnknownLinuxGnu => &["cc", "c++", "make", "pkg-config", "patch"],
        Platform::Aarch64AppleDarwin => &["cc", "c++", "make"],
    };
    let missing: Vec<&str> = required
        .iter()
        .copied()
        .filter(|program| on_path(program).is_none())
        .collect();
    if missing.is_empty() {
        checks.push(check(
            "c-toolchain",
            Level::Ok,
            format!("{} on PATH", required.join(", ")),
        ));
    } else {
        // Bubblewrap is not one of `required`; its hint belongs on the
        // sandbox check, which is the one that tests it.
        let hint = crate::kernel::platform::install_hint(
            platform,
            crate::kernel::platform::HostPackages::CToolchain,
        );
        checks.push(check(
            "c-toolchain",
            Level::Warn,
            format!(
                "missing {}; pure wheels and lockfile installs work, native builds will not ({hint})",
                missing.join(", ")
            ),
        ));
    }
}

/// Everything that needs a known host: the per-tailor probes in registry
/// order, then the sandbox, then the C toolchain.
fn platform_checks(platform: Platform, project: Option<&ProjectRoot>, checks: &mut Vec<Check>) {
    for tailor in tailors::registry() {
        let Some(project) = project else {
            break;
        };
        for probe in tailor.doctor(platform, project) {
            let level = if probe.ok { Level::Ok } else { Level::Fail };
            checks.push(check(probe.name, level, probe.detail));
        }
    }
    match sandbox::probe(platform) {
        Ok(detail) => checks.push(check("sandbox", Level::Ok, detail)),
        // The error already carries this host's install command and the
        // reason; doctor only adds what the sandbox is for.
        Err(error) => checks.push(check(
            "sandbox",
            Level::Fail,
            format!("{error}; sdists, npm install scripts, and 'tog build' need it"),
        )),
    }
    c_toolchain_check(platform, checks);
}

/// `tog doctor --isolation`: the engines that can isolate a lock-changing
/// tool, strongest first, and whether any can. The container engine is
/// probed through the store lease, so a store that cannot be opened or is
/// busy leaves that row unknown (a warning). An interrupt during a probe is
/// returned.
pub fn isolation_doctor(store: DoctorStore) -> io::Result<Vec<Check>> {
    let mut checks = Vec::new();
    if Platform::host().ok() != Some(Platform::X86_64UnknownLinuxGnu) {
        // macOS has one engine, Seatbelt: the ordinary sandbox row.
        let platform = Platform::host()?;
        checks.push(match sandbox::probe(platform) {
            Ok(detail) => check("sandbox", Level::Ok, detail),
            Err(error) => check("sandbox", Level::Fail, error.to_string()),
        });
        return Ok(checks);
    }
    let interrupted = |error: &io::Error| crate::kernel::supervise::stop_signal(error).is_some();
    let activity = match store {
        Ok((_, Some(activity))) => Some(activity),
        _ => None,
    };
    let bwrap = match sandbox::bwrap_preflight_with_activity(activity) {
        Ok(path) => Ok(format!("bubblewrap at {}", path.display())),
        Err(error) if interrupted(&error) => return Err(error),
        Err(error) => Err(error.to_string()),
    };
    let podman = match activity {
        Some(activity) => match crate::kernel::resolve::container::preflight(activity) {
            Ok(path) => Some(Ok(format!("rootless podman at {}", path.display()))),
            Err(error) if interrupted(&error) => return Err(error),
            Err(error) => Some(Err(error.to_string())),
        },
        None => None,
    };
    let any = bwrap.is_ok() || matches!(podman, Some(Ok(_)));
    let missing = if any { Level::Warn } else { Level::Fail };
    checks.push(match bwrap {
        Ok(detail) => check(
            "bubblewrap",
            Level::Ok,
            format!("{detail}; resolvers run here"),
        ),
        Err(reason) => check(
            "bubblewrap",
            missing,
            format!("{reason}; fix: install bubblewrap and allow it unprivileged user namespaces"),
        ),
    });
    checks.push(match podman {
        Some(Ok(detail)) if checks[0].level == Level::Ok => check(
            "container",
            Level::Ok,
            format!("{detail}; used only where bubblewrap cannot run"),
        ),
        Some(Ok(detail)) => check(
            "container",
            Level::Ok,
            format!("{detail}; resolvers run here"),
        ),
        Some(Err(reason)) => check(
            "container",
            missing,
            format!(
                "{reason}; fix: install podman, with subordinate IDs for this user in \
                 /etc/subuid and /etc/subgid, on cgroup v2"
            ),
        ),
        None => check(
            "container",
            Level::Warn,
            "not checked: the podman probe needs the store, which is unavailable or busy",
        ),
    });
    checks.push(check(
        "isolation-helper",
        if any { Level::Ok } else { Level::Fail },
        "tog-isolate is not part of this build of tog; bubblewrap or podman isolates instead",
    ));
    Ok(checks)
}

/// Which policy sources are in force, in the order they are consulted.
fn policy_check(project: Option<&ProjectRoot>, checks: &mut Vec<Check>) {
    let strict = std::env::var("TOG_STRICT").as_deref() == Ok("1");
    let policy_file = std::env::var_os("TOG_POLICY")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME")
                .map(|home| Path::new(&home).join(".tog/policy.toml"))
                .filter(|path| path.is_file())
        });
    let mut policy = Vec::new();
    if strict {
        policy.push("TOG_STRICT=1".to_string());
    }
    if let Some(path) = policy_file {
        policy.push(path.display().to_string());
    }
    if project.is_some_and(|project| project.is_input_file(Path::new(".tog/policy.toml"))) {
        policy.push(".tog/policy.toml".to_string());
    }
    checks.push(check(
        "policy",
        Level::Ok,
        if policy.is_empty() {
            "permissive (no policy file, TOG_STRICT unset)".to_string()
        } else {
            policy.join(", ")
        },
    ));
}

/// What is here and whether it has been synced. Detection is the same test
/// `sync` uses, so this never disagrees with what a sync would do.
fn project_check(dir: &Path, project: &io::Result<Option<ProjectRoot>>, checks: &mut Vec<Check>) {
    let found = match project {
        Ok(Some(project)) => tailors::detected_in(project).map(|found| {
            found
                .into_iter()
                .map(|tailor| tailor.id())
                .collect::<Vec<_>>()
        }),
        Ok(None) => Ok(Vec::new()),
        Err(error) => Err(io::Error::new(error.kind(), error.to_string())),
    };
    match found {
        Ok(found) if found.is_empty() => checks.push(check(
            "project",
            Level::Ok,
            format!("no project in {} (nothing to sync here)", dir.display()),
        )),
        Ok(found) => {
            let held = project.as_ref().ok().and_then(Option::as_ref);
            let synced: Vec<String> = held
                .map_or(Ok(Vec::new()), closures_in)
                .map(|closures| closures.into_iter().map(|c| c.ecosystem).collect())
                .unwrap_or_default();
            let unsynced: Vec<&str> = found
                .iter()
                .copied()
                .filter(|name| !synced.iter().any(|s| s == name))
                .collect();
            checks.push(check(
                "project",
                Level::Ok,
                if unsynced.is_empty() {
                    format!(
                        "{} (synced; 'tog status' checks the inputs)",
                        found.join(", ")
                    )
                } else {
                    format!(
                        "{} found; not synced yet: {} (run 'tog')",
                        found.join(", "),
                        unsynced.join(", ")
                    )
                },
            ));
        }
        Err(error) => checks.push(check("project", Level::Warn, error.to_string())),
    }
}

/// The order the checks are pushed in is the order they print in, and that
/// order is the contract: host, then store, then everything that needs a
/// known host, then the two project-local answers.
/// The project is opened once, and every project read goes through it.
pub fn doctor(dir: &Path, store: DoctorStore) -> Vec<Check> {
    let mut checks = Vec::new();
    let platform = host_platform_check(&mut checks);
    store_checks(store, &mut checks);
    let project = open_project(dir);
    let held = project.as_ref().ok().and_then(Option::as_ref);
    if let Some(platform) = platform {
        platform_checks(platform, held, &mut checks);
    }
    policy_check(held, &mut checks);
    project_check(dir, &project, &mut checks);
    checks
}
pub fn render_doctor(checks: &[Check], json: bool) -> io::Result<String> {
    if json {
        let value = json!({
            "ok": checks.iter().all(|check| check.level != Level::Fail),
            "checks": checks.iter().map(|check| json!({
                "name": check.name,
                "level": match check.level { Level::Ok => "ok", Level::Warn => "warn", Level::Fail => "fail" },
                "detail": check.detail,
            })).collect::<Vec<_>>(),
        });
        return Ok(serde_json::to_string_pretty(&value)? + "\n");
    }
    let width = checks
        .iter()
        .map(|check| check.name.len())
        .max()
        .unwrap_or(0);
    let mut out = String::new();
    for check in checks {
        // The words are the ones CLI.md promises, in the spelling it
        // promises them in: ok, warn, fail.
        let level = match check.level {
            Level::Ok => "ok  ",
            Level::Warn => "warn",
            Level::Fail => "fail",
        };
        out.push_str(&format!(
            "{level}  {:width$}  {}\n",
            check.name, check.detail
        ));
    }
    let failures = checks
        .iter()
        .filter(|check| check.level == Level::Fail)
        .count();
    if failures > 0 {
        out.push_str(&format!(
            "\n{failures} check{} failed.\n",
            if failures == 1 { "" } else { "s" }
        ));
    }
    Ok(out)
}

/// Publish a `tog-toolchain.toml` section for this ecosystem and hand
/// back the bundle id the closure has to record to count as synced
/// against it. A lock-aware sync writes both together, and a fixture
/// with only one of them is testing the lock verdict rather than
/// whatever it meant to test. Shared with the `audit` tests, which judge
/// the same lock.
#[cfg(test)]
pub(crate) fn with_toolchain_lock(dir: &Path, ecosystem: &str, mut body: Value) -> Value {
    let Some(tailor) = tailors::by_id(ecosystem) else {
        return body;
    };
    let lock_ecosystem = tailor.lock_ecosystem();
    let root = ProjectRoot::open(dir).unwrap();
    let mut lock = ToolchainLock::read_via(&root)
        .unwrap()
        .unwrap_or_else(|| ToolchainLock::new(env!("CARGO_PKG_VERSION")));
    let catalog = tailor.toolchain_catalog().unwrap();
    let rows = input::discover(&root, lock_ecosystem).unwrap();
    let bundle = crate::kernel::toolchain::select_for(&catalog, lock_ecosystem, &rows)
        .unwrap()
        .clone();
    lock.set_ecosystem(lock_ecosystem, &bundle, &rows).unwrap();
    fs::write(dir.join(LOCK_PATH), lock.canonical_bytes()).unwrap();
    // The helper decision the same sync would record beside it.
    let present = tailors::detected(dir).unwrap();
    let mut helpers = serde_json::Map::new();
    for helper in tailor.helpers() {
        let locked = if present.iter().any(|t| t.lock_ecosystem() == *helper) {
            lock.ecosystem(helper)
                .map(|section| section.bundle_id().to_string())
        } else {
            None
        };
        let decided = locked.or_else(|| {
            tailor
                .default_helper(helper)
                .unwrap()
                .map(|selected| selected.bundle_id())
        });
        helpers.insert(
            (*helper).to_string(),
            decided.map_or(Value::Null, Value::String),
        );
    }
    body["toolchain"] = json!({"bundle_id": bundle.bundle_id(), "helpers": helpers});
    body
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    /// Doctor's realized-toolchain row reads `Tailor::toolchain_kinds`; each
    /// is a kind its own tailor or a kernel provider registers (#191), and
    /// every ecosystem has one.
    #[test]
    fn toolchain_kinds_are_registered_object_kinds() {
        for tailor in tailors::registry() {
            assert!(!tailor.toolchain_kinds().is_empty(), "{}", tailor.id());
            for kind in tailor.toolchain_kinds() {
                assert!(
                    tailor
                        .object_kinds()
                        .iter()
                        .chain(crate::kernel::provider::objects::KINDS)
                        .any(|row| row.kind == *kind),
                    "{}: toolchain kind {kind} has no object-kind row",
                    tailor.id()
                );
            }
        }
    }

    use crate::kernel::testutil::TempDir;

    /// A FIFO or a symlink where an object record belongs is skipped: the
    /// toolchain listing returns instead of blocking on the FIFO's open.
    #[test]
    fn realized_toolchains_skips_what_is_not_a_regular_record() {
        let temp = TempDir::new();
        let store = Store {
            root: temp.0.join("store"),
        };
        let meta = store.root.join("meta");
        fs::create_dir_all(&meta).unwrap();
        let fifo = std::ffi::CString::new(meta.join("a.json").as_os_str().as_bytes()).unwrap();
        // SAFETY: the NUL-terminated name lives through the call.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        let outside = temp.0.join("outside.json");
        fs::write(
            &outside,
            r#"{"identity":{"kind":"python","name":"cpython","version":"9.9.9"}}"#,
        )
        .unwrap();
        std::os::unix::fs::symlink(&outside, meta.join("b.json")).unwrap();
        fs::write(meta.join("c.json"), "not json").unwrap();
        assert_eq!(realized_toolchains(&store).unwrap(), Vec::<String>::new());
    }

    /// Names and records come from one held `meta/`: a `meta/` swapped
    /// for a decoy after it is opened shows neither the decoy's toolchain
    /// nor loses the held directory's.
    #[test]
    fn realized_toolchains_reads_the_held_meta_directory() {
        let temp = TempDir::new();
        let store = Store {
            root: temp.0.join("store"),
        };
        let meta = store.root.join("meta");
        fs::create_dir_all(&meta).unwrap();
        let record = |version: &str| {
            format!(r#"{{"identity":{{"kind":"cpython","name":"cpython","version":"{version}"}}}}"#)
        };
        fs::write(meta.join("held.json"), record("3.12.0")).unwrap();
        let (from, to) = (meta.clone(), store.root.join("meta-moved"));
        crate::kernel::store::HELD_META_FAILPOINT.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move || {
                fs::rename(&from, &to).unwrap();
                fs::create_dir(&from).unwrap();
                fs::write(from.join("held.json"), record("9.9.9")).unwrap();
                fs::write(from.join("decoy.json"), record("9.9.8")).unwrap();
            }))
        });
        let found = realized_toolchains(&store);
        crate::kernel::store::HELD_META_FAILPOINT.with(|slot| *slot.borrow_mut() = None);
        assert_eq!(found.unwrap(), vec!["cpython 3.12.0".to_string()]);
    }

    fn write_closure(dir: &Path, ecosystem: &str, platform: &str, body: Value) {
        let body = with_toolchain_lock(dir, ecosystem, body);
        let closures = dir.join(".tog/closures");
        fs::create_dir_all(&closures).unwrap();
        fs::write(
            closures.join(format!("{ecosystem}.json")),
            serde_json::to_vec_pretty(&json!({
                "schema": "closure/1",
                "ecosystem": ecosystem,
                "platform": platform,
                "projected_at": 1,
                "body": body,
            }))
            .unwrap(),
        )
        .unwrap();
    }

    /// A report reads the project it opened: a synced project renamed away
    /// and replaced by an unsynced one at its path is still reported as
    /// the one held, while a fresh open by path sees the replacement.
    #[test]
    fn status_reads_the_project_it_opened() {
        let temp = TempDir::new();
        let dir = temp.0.join("p");
        let platform = Platform::host().unwrap();
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("requirements.txt"), "six\n").unwrap();
        let env = temp.0.join("env");
        fs::create_dir_all(env.join("bin")).unwrap();
        std::os::unix::fs::symlink(&env, dir.join(".venv")).unwrap();
        write_closure(
            &dir,
            "python",
            platform.triple(),
            json!({
                "env_object": env,
                "inputs": [{"path": "requirements.txt", "sha256":
                    crate::kernel::resolve::record::sha256_hex(b"six\n")}],
                "exceptions": [],
            }),
        );
        let project = ProjectRoot::open(&dir).unwrap();
        fs::rename(&dir, temp.0.join("moved")).unwrap();
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("requirements.txt"), "six\n").unwrap();
        let held = status_in(platform, &project).unwrap();
        assert_eq!(held.len(), 1);
        assert_eq!(held[0].state, State::Synced);
        assert_eq!(closures_in(&project).unwrap().len(), 1);
        assert_eq!(status(platform, &dir).unwrap()[0].state, State::NotSynced);
    }

    #[test]
    fn detects_every_ecosystem_from_its_inputs() {
        let temp = TempDir::named("detect");
        assert!(detected(&temp.0).unwrap().is_empty());
        fs::write(temp.0.join("requirements.txt"), "six\n").unwrap();
        fs::write(temp.0.join("package.json"), "{}").unwrap();
        fs::write(temp.0.join("Cargo.toml"), "[package]\nname='x'\n").unwrap();
        fs::write(temp.0.join("go.mod"), "module x\n").unwrap();
        fs::write(temp.0.join("Gemfile"), "").unwrap();
        fs::write(temp.0.join("mix.exs"), "").unwrap();
        fs::write(temp.0.join("app.csproj"), "").unwrap();
        assert_eq!(detected(&temp.0).unwrap(), ecosystems());
    }

    #[test]
    fn listing_reads_every_closure_shape() {
        let temp = TempDir::named("ls");
        let host = Platform::host().unwrap().triple();
        write_closure(
            &temp.0,
            "python",
            host,
            json!({"env_object": "/s/objects/e", "python": {"version": "3.12.14"},
                   "plan": {"python_version": "3.12.14", "packages": [
                       {"name": "six", "version": "1.17.0", "filename": "six-1.17.0-py2.py3-none-any.whl"}]}}),
        );
        write_closure(
            &temp.0,
            "node",
            host,
            json!({"node_version": "24.0.0", "packages": [
                {"path": "node_modules/a", "version": "1.0.0"},
                {"path": "node_modules/a/node_modules/@s/b", "version": "2.0.0"}]}),
        );
        write_closure(
            &temp.0,
            "cargo",
            host,
            json!({"plan": {"rust_version": "1.96.1", "crates": [{"name": "serde", "version": "1.0.0", "sha256": "ab"}]}}),
        );
        write_closure(
            &temp.0,
            "go",
            host,
            json!({"plan": {"go_version": "1.25", "modules": [{"path": "github.com/x/y", "version": "v1.2.3"}]}}),
        );
        write_closure(
            &temp.0,
            "ruby",
            host,
            json!({"plan": {"ruby_version": "3.4.6", "bundler_version": "2.6", "gems": [{"name": "rake", "version": "13.0", "full_name": "rake-13.0"}]}}),
        );
        write_closure(
            &temp.0,
            "elixir",
            host,
            json!({"plan": {"elixir_version": "1.18", "otp_version": "27", "deps": [{"app": "jason", "package": "jason", "version": "1.4"}]}}),
        );
        write_closure(
            &temp.0,
            "dotnet",
            host,
            json!({"plan": {"sdk_version": "9.0", "packages": [{"id": "Newtonsoft.Json", "version": "13.0", "content_hash": "x"}]}}),
        );

        let all = closures(&temp.0).unwrap();
        assert_eq!(
            all.iter().map(|c| c.ecosystem.as_str()).collect::<Vec<_>>(),
            ecosystems()
        );
        let node = listing(&all[1]);
        assert_eq!(
            node.toolchain,
            vec![("node".to_string(), "24.0.0".to_string())]
        );
        assert_eq!(node.packages[0].name, "@s/b");
        assert_eq!(node.packages[1].name, "a");
        let text = ls(&temp.0, None, false, false).unwrap();
        // Every shape renders its own toolchain line and its packages, in
        // ecosystem order; node's nested path is listed by package name.
        assert_eq!(
            text,
            concat!(
                "python  (cpython 3.12.14; 1 package)\n  six  1.17.0\n\n",
                "node  (node 24.0.0; 2 packages)\n  @s/b  2.0.0\n  a     1.0.0\n\n",
                "cargo  (rust 1.96.1; 1 package)\n  serde  1.0.0\n\n",
                "go  (go 1.25; 1 package)\n  github.com/x/y  v1.2.3\n\n",
                "ruby  (ruby 3.4.6, bundler 2.6; 1 package)\n  rake  13.0\n\n",
                "elixir  (elixir 1.18, otp 27; 1 package)\n  jason  1.4\n\n",
                "dotnet  (dotnet-sdk 9.0; 1 package)\n  Newtonsoft.Json  13.0\n",
            )
        );
        let only = ls(&temp.0, Some("go"), false, true).unwrap();
        assert_eq!(only, "go  (go 1.25; 1 package)\n  github.com/x/y  v1.2.3\n");
        let json_text = ls(&temp.0, Some("cargo"), true, false).unwrap();
        let value: Value = serde_json::from_str(&json_text).unwrap();
        assert_eq!(value["ecosystems"][0]["packages"][0]["name"], "serde");
        assert_eq!(value["ecosystems"][0]["toolchain"][0]["version"], "1.96.1");

        let empty = TempDir::named("ls-empty");
        let error = ls(&empty.0, None, false, false).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        assert!(error.to_string().contains("run 'tog' first"));
        assert_eq!(
            ls(&temp.0, Some("python"), false, false).unwrap(),
            "python  (cpython 3.12.14; 1 package)\n  six  1.17.0\n"
        );
        let missing = {
            let solo = TempDir::named("ls-solo");
            write_closure(
                &solo.0,
                "go",
                host,
                json!({"plan": {"go_version": "1.25", "modules": []}}),
            );
            ls(&solo.0, Some("python"), false, false)
                .unwrap_err()
                .to_string()
        };
        assert!(missing.contains("no python closure here"), "{missing}");
    }

    /// An older `tog fmt` left `.tog/closures/rustfmt.json` at a Cargo
    /// workspace root. It is not a closure any more: `status`, `ls`, and
    /// everything else that reads closures skip it, so the workspace reads
    /// exactly as it would without it.
    #[test]
    fn a_leftover_rustfmt_record_is_skipped() {
        let temp = TempDir::named("leftover-rustfmt");
        let platform = Platform::host().unwrap();
        let host = platform.triple();
        let dir = &temp.0;
        fs::write(dir.join("Cargo.toml"), "[package]\nname='x'\n").unwrap();
        fs::write(dir.join("Cargo.lock"), "version = 4\n").unwrap();
        fs::create_dir_all(dir.join(".tog/cargo-home")).unwrap();
        write_closure(
            dir,
            "cargo",
            host,
            json!({"cargo_lock_sha256": sha256_file(&dir.join("Cargo.lock")).unwrap(),
                   "plan": {"rust_version": "1.96.1", "crates": []}}),
        );
        fs::write(
            dir.join(".tog/closures/rustfmt.json"),
            serde_json::to_vec_pretty(&json!({
                "schema": "closure/1",
                "ecosystem": "rustfmt",
                "platform": host,
                "projected_at": 1,
                "body": {"rust_version": "1.96.1", "rustfmt_object": {"id": "rustfmt-id"}},
            }))
            .unwrap(),
        )
        .unwrap();
        let read = closures(dir).unwrap();
        assert_eq!(
            read.iter()
                .map(|c| c.ecosystem.as_str())
                .collect::<Vec<_>>(),
            ["cargo"]
        );
        let rows = status(platform, dir).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].ecosystem, "cargo");
        assert_eq!(rows[0].state, State::Synced);
        let listed = ls(dir, None, false, false).unwrap();
        assert!(!listed.contains("rustfmt"), "{listed}");
        // The leftover alone is nothing synced.
        fs::remove_file(dir.join(".tog/closures/cargo.json")).unwrap();
        assert!(closures(dir).unwrap().is_empty());
        assert_eq!(
            rows_state(&status(platform, dir).unwrap()),
            [State::NotSynced]
        );
    }

    fn rows_state(rows: &[EcosystemStatus]) -> Vec<State> {
        rows.iter().map(|row| row.state.clone()).collect()
    }

    /// Re-lock `lock_ecosystem` on a bundle whose first artifact row names
    /// other bytes: the lock-side change `tog update --toolchain` makes when
    /// a helper ecosystem moves to another release.
    fn relock_elsewhere(dir: &Path, lock_ecosystem: &str) {
        let root = ProjectRoot::open(dir).unwrap();
        let mut lock = ToolchainLock::read_via(&root).unwrap().unwrap();
        let tailor = tailors::registry()
            .iter()
            .find(|tailor| tailor.lock_ecosystem() == lock_ecosystem)
            .unwrap();
        let rows = input::discover(&root, lock_ecosystem).unwrap();
        let mut bundle = crate::kernel::toolchain::select_for(
            &tailor.toolchain_catalog().unwrap(),
            lock_ecosystem,
            &rows,
        )
        .unwrap()
        .clone();
        bundle.artifacts[0].digest = crate::kernel::fetch::Digest::sha256(&"e".repeat(64)).unwrap();
        lock.set_ecosystem(lock_ecosystem, &bundle, &rows).unwrap();
        fs::write(dir.join(LOCK_PATH), lock.canonical_bytes()).unwrap();
    }

    /// A closure records the helper toolchains its tailor built with, and
    /// `status` holds it to the decision a sync would make now, in both
    /// directions tog has: node-gyp's Python for Node, an sdist's Rust for
    /// Python. Re-locking the helper ecosystem, or removing its manifest so
    /// the helper falls back to the tailor's default, puts the closure out
    /// of step even though its own inputs and lock section are unchanged.
    #[test]
    fn status_holds_a_closure_to_its_helper_toolchains() {
        let cases: [(&str, &str, &[(&str, &str)]); 2] = [
            (
                "node",
                "python",
                &[
                    ("requirements.txt", "six==1.17.0\n"),
                    (".python-version", "3.13\n"),
                ],
            ),
            (
                "python",
                "rust",
                &[
                    ("Cargo.toml", "[package]\nname='x'\n"),
                    ("Cargo.lock", "version = 4\n"),
                ],
            ),
        ];
        for (ecosystem, helper, helper_files) in cases {
            let temp = TempDir::named("status-helpers");
            let dir = &temp.0;
            fs::write(dir.join("package.json"), "{}\n").unwrap();
            fs::write(dir.join("requirements.txt"), "six==1.17.0\n").unwrap();
            for (name, text) in helper_files {
                fs::write(dir.join(name), text).unwrap();
            }
            let owner = tailors::detected(dir)
                .unwrap()
                .into_iter()
                .find(|tailor| tailor.lock_ecosystem() == helper)
                .unwrap()
                .id();
            // One sync: the helper's section, then the closure beside it.
            with_toolchain_lock(dir, owner, json!({}));
            let body = with_toolchain_lock(dir, ecosystem, json!({}));
            let recorded = body["toolchain"]["helpers"][helper].clone();
            assert!(recorded.is_string(), "{ecosystem}: {body}");
            assert_eq!(
                helper_state(&ProjectRoot::open(dir).unwrap(), ecosystem, &body).unwrap(),
                None
            );
            let default = tailors::by_id(ecosystem)
                .unwrap()
                .default_helper(helper)
                .unwrap()
                .map(|selected| json!(selected.bundle_id()))
                .unwrap_or(Value::Null);
            assert_ne!(recorded, default, "{ecosystem}: the project's own helper");

            // The helper ecosystem re-locked on other bytes.
            relock_elsewhere(dir, helper);
            let expected = State::Changed(vec![format!(
                "the {helper} toolchain {ecosystem} builds with"
            )]);
            assert_eq!(
                helper_state(&ProjectRoot::open(dir).unwrap(), ecosystem, &body).unwrap(),
                Some(expected.clone()),
                "{ecosystem}: helper lock change"
            );
            let body = with_toolchain_lock(dir, ecosystem, json!({}));
            assert_eq!(
                helper_state(&ProjectRoot::open(dir).unwrap(), ecosystem, &body).unwrap(),
                None
            );

            // The helper's manifest removed: its section may linger in the
            // lock, but a sync now decides the tailor's default.
            for (name, _) in helper_files {
                fs::remove_file(dir.join(name)).unwrap();
            }
            assert_eq!(
                helper_state(&ProjectRoot::open(dir).unwrap(), ecosystem, &body).unwrap(),
                Some(expected),
                "{ecosystem}: helper input removed"
            );
            let mut resynced = body.clone();
            resynced["toolchain"]["helpers"][helper] = default;
            assert_eq!(
                helper_state(&ProjectRoot::open(dir).unwrap(), ecosystem, &resynced).unwrap(),
                None
            );
        }
    }

    /// A Go closure that joined a resolution record: a dependency added to
    /// go.mod alone (same `go` directive, same go.sum) leaves every other
    /// status check synced, and the record's digest shows the change.
    #[test]
    fn status_reports_a_go_lock_its_resolution_record_no_longer_describes() {
        let temp = TempDir::named("status-record");
        let platform = Platform::host().unwrap();
        let dir = &temp.0;
        fs::write(dir.join("go.mod"), "module x\n").unwrap();
        fs::write(dir.join("go.sum"), "sum\n").unwrap();
        let digest = |name: &str| sha256_file(&dir.join(name)).unwrap();
        write_closure(
            dir,
            "go",
            platform.triple(),
            json!({"go_sum_sha256": digest("go.sum"),
                   "plan": {"go_version": "1.27.0", "modules": []},
                   "resolution": {"outputs": {"go.mod": digest("go.mod"), "go.sum": digest("go.sum")},
                                  "inputs": {}, "exceptions": []}}),
        );
        let go_row = |rows: &[EcosystemStatus]| {
            rows.iter()
                .find(|row| row.ecosystem == "go")
                .unwrap()
                .state
                .clone()
        };
        assert_eq!(go_row(&status(platform, dir).unwrap()), State::Synced);
        fs::write(
            dir.join("go.mod"),
            "module x\n\nrequire example.com/y v1.0.0\n",
        )
        .unwrap();
        assert_eq!(
            go_row(&status(platform, dir).unwrap()),
            State::Changed(vec!["go.mod".into()])
        );
    }

    #[test]
    fn status_tracks_inputs_locks_projections_and_platforms() {
        let temp = TempDir::named("status");
        let platform = Platform::host().unwrap();
        let host = platform.triple();
        let dir = &temp.0;
        fs::write(dir.join("requirements.txt"), "six==1.17.0\n").unwrap();
        fs::write(dir.join("go.mod"), "module x\n").unwrap();
        fs::write(dir.join("go.sum"), "sum\n").unwrap();
        fs::write(dir.join("Cargo.toml"), "[package]\nname='x'\n").unwrap();
        fs::write(dir.join("Cargo.lock"), "version = 4\n").unwrap();

        // Nothing synced yet.
        let rows = status(platform, dir).unwrap();
        assert!(rows.iter().all(|row| row.state == State::NotSynced));
        assert_eq!(rows.len(), 3);

        // Python: projection + recorded inputs.
        let env = dir.join("env-object");
        fs::create_dir_all(env.join("bin")).unwrap();
        std::os::unix::fs::symlink(&env, dir.join(".venv")).unwrap();
        // Go: recorded lock hash; cargo: projection missing.
        write_closure(
            dir,
            "go",
            host,
            json!({"go_sum_sha256": sha256_file(&dir.join("go.sum")).unwrap(), "plan": {"go_version": "1.27.0", "modules": []}}),
        );
        write_closure(
            dir,
            "cargo",
            host,
            json!({"cargo_lock_sha256": sha256_file(&dir.join("Cargo.lock")).unwrap(), "plan": {"rust_version": "1.96.1", "crates": []}}),
        );
        // Python last: its sdists build on the Rust the cargo section just
        // locked, and one sync records both together.
        let requirements = sha256_file(&dir.join("requirements.txt")).unwrap();
        write_closure(
            dir,
            "python",
            host,
            json!({"env_object": env, "python": {"version": "3.12.14"},
                   "plan": {"packages": []},
                   "inputs": [{"path": "requirements.txt", "sha256": requirements}],
                   "exceptions": [],
                   "optional_groups_skipped": [
                       {"group": "docs", "detail": "extra, not requested",
                        "requirements": ["sphinx", "furo"]}]}),
        );
        let rows = status(platform, dir).unwrap();
        assert_eq!(rows[0].state, State::Synced);
        // An unrequested group is listed under the row, never counted as an
        // exception (#71).
        assert!(rows[0].exceptions.is_empty());
        assert_eq!(rows[0].optional_groups_skipped[0].group, "docs");
        assert_eq!(
            rows[1].state,
            State::ProjectionMissing(".tog/cargo-home".into())
        );
        assert_eq!(rows[2].state, State::Synced);
        let text = render_status(dir, &rows, false).unwrap();
        assert!(
            text.contains("python  synced      (cpython 3.12.14; 0 packages)"),
            "{text}"
        );
        assert!(
            text.contains(
                "          optional    docs (2 requirements) not installed: extra, not requested"
            ),
            "{text}"
        );
        assert!(!text.contains("policy exception"), "{text}");
        assert!(
            text.contains("cargo   missing     .tog/cargo-home"),
            "{text}"
        );

        // A malformed optional-group list on a row that is not synced keeps
        // the row's state and is reported beside it, as an unreadable
        // exception list is (#552).
        write_closure(
            dir,
            "cargo",
            host,
            json!({"cargo_lock_sha256": sha256_file(&dir.join("Cargo.lock")).unwrap(),
                   "plan": {"rust_version": "1.96.1", "crates": []},
                   "optional_groups_skipped": "not a list"}),
        );
        let rows = status(platform, dir).unwrap();
        assert_eq!(
            rows[1].state,
            State::ProjectionMissing(".tog/cargo-home".into())
        );
        let error = rows[1].optional_groups_skipped_error.clone().unwrap();
        assert!(
            error.contains("malformed optional_groups_skipped"),
            "{error}"
        );
        let text = render_status(dir, &rows, false).unwrap();
        assert!(
            text.contains("          optional    unreadable  ") && text.contains(&error),
            "{text}"
        );
        let json: Value = serde_json::from_str(&render_status(dir, &rows, true).unwrap()).unwrap();
        assert_eq!(
            json["ecosystems"][1]["optional_groups_skipped_error"],
            json!(error)
        );
        assert_eq!(
            json["ecosystems"][0]["optional_groups_skipped_error"],
            Value::Null
        );
        write_closure(
            dir,
            "cargo",
            host,
            json!({"cargo_lock_sha256": sha256_file(&dir.join("Cargo.lock")).unwrap(), "plan": {"rust_version": "1.96.1", "crates": []}}),
        );

        // A pre-field Go closure cannot verify the selected toolchain, even
        // when its recorded go.sum hash is still current.
        write_closure(
            dir,
            "go",
            host,
            json!({"go_sum_sha256": sha256_file(&dir.join("go.sum")).unwrap(), "plan": {"modules": []}}),
        );
        let rows = status(platform, dir).unwrap();
        assert_eq!(
            rows[2].state,
            State::Unchecked(
                "recorded Go version is missing; run 'tog' once to record the selected toolchain"
                    .into()
            )
        );

        write_closure(
            dir,
            "go",
            host,
            json!({"go_sum_sha256": sha256_file(&dir.join("go.sum")).unwrap(), "plan": {"go_version": "1.27.0", "modules": []}}),
        );

        // The selected Go version is an input too, even when the projection
        // and go.sum still exist. The lock written beside the closure sees
        // the same move, and its verdict names the verb that resolves it.
        fs::write(dir.join("go.mod"), "module x\n\ngo 1.28\n").unwrap();
        let rows = status(platform, dir).unwrap();
        assert_eq!(
            rows[2].state,
            State::Changed(vec![
                "tog-toolchain.toml stale: go.mod go: recorded absent, now 1.28; run 'tog update --toolchain go'"
                    .into()
            ])
        );
        // Without a lock there is nothing to refuse, and the closure's own
        // toolchain check is what reports.
        let lock_bytes = fs::read(dir.join(LOCK_PATH)).unwrap();
        fs::remove_file(dir.join(LOCK_PATH)).unwrap();
        let rows = status(platform, dir).unwrap();
        assert_eq!(
            rows[2].state,
            State::Changed(vec!["go.mod (Go toolchain selection unavailable)".into()])
        );
        fs::write(dir.join(LOCK_PATH), lock_bytes).unwrap();
        fs::write(dir.join("go.mod"), "module x\n").unwrap();

        // Edit the manifest and the lock: both reported by name.
        fs::write(dir.join("requirements.txt"), "six==1.16.0\n").unwrap();
        fs::write(dir.join("go.sum"), "changed\n").unwrap();
        fs::create_dir_all(dir.join(".tog/cargo-home")).unwrap();
        let rows = status(platform, dir).unwrap();
        assert_eq!(
            rows[0].state,
            State::Changed(vec!["requirements.txt".into()])
        );
        assert_eq!(rows[1].state, State::Synced);
        assert_eq!(rows[2].state, State::Changed(vec!["go.sum".into()]));
        let json_text = render_status(dir, &rows, true).unwrap();
        let value: Value = serde_json::from_str(&json_text).unwrap();
        assert_eq!(value["synced"], false);
        assert_eq!(value["ecosystems"][0]["state"], "changed");
        assert_eq!(value["ecosystems"][0]["detail"][0], "requirements.txt");

        // A closure without recorded inputs cannot be checked, and an
        // unchecked closure is not a synced one: it fails the gate, says
        // why on its own row, and the summary counts it.
        write_closure(
            dir,
            "python",
            host,
            json!({"env_object": env, "python": {"version": "3.12.14"}, "plan": {"packages": []}}),
        );
        let rows = status(platform, dir).unwrap();
        assert!(matches!(rows[0].state, State::Unchecked(_)));
        assert!(!rows[0].is_synced());
        let text = render_status(dir, &rows, false).unwrap();
        assert!(
            text.contains("python  unchecked   inputs were not"),
            "{text}"
        );
        assert!(text.contains("of 3 synced; 1 unchecked"), "{text}");
        assert!(
            text.contains("Exit status is 0 only when every ecosystem is synced."),
            "{text}"
        );
        let value: Value = serde_json::from_str(&render_status(dir, &rows, true).unwrap()).unwrap();
        assert_eq!(value["synced"], false);
        assert_eq!(value["ecosystems"][0]["state"], "unchecked");

        // A foreign platform is reported, not compared.
        write_closure(
            dir,
            "go",
            "other-platform",
            json!({"go_sum_sha256": "x", "plan": {}}),
        );
        let rows = status(platform, dir).unwrap();
        assert_eq!(
            rows[2].state,
            State::ForeignPlatform("other-platform".into())
        );
    }

    /// The four verdicts the committed lock can add to a row that is
    /// otherwise synced, and the one it stays quiet for.
    #[test]
    fn status_reports_the_toolchain_lock_verdicts() {
        let temp = TempDir::named("status-lock");
        let platform = Platform::host().unwrap();
        let dir = &temp.0;
        fs::write(dir.join("requirements.txt"), "six==1.17.0\n").unwrap();
        fs::write(dir.join(".python-version"), "3.12.14\n").unwrap();
        let env = dir.join("env-object");
        fs::create_dir_all(env.join("bin")).unwrap();
        std::os::unix::fs::symlink(&env, dir.join(".venv")).unwrap();
        let requirements = sha256_file(&dir.join("requirements.txt")).unwrap();
        // `write_closure` publishes the matching lock, so this row starts
        // out synced with the lock having nothing to add.
        write_closure(
            dir,
            "python",
            platform.triple(),
            json!({"env_object": env, "python": {"version": "3.12.14"},
                   "plan": {"packages": []},
                   "inputs": [{"path": "requirements.txt", "sha256": requirements}]}),
        );
        assert_eq!(status(platform, dir).unwrap()[0].state, State::Synced);

        // A moved source: the lock is stale, and the row names both values
        // and the only verb that may move a locked runtime.
        fs::write(dir.join(".python-version"), "3.13.15\n").unwrap();
        let State::Changed(rows) = &status(platform, dir).unwrap()[0].state else {
            panic!("a moved toolchain source did not report the lock");
        };
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert!(
            rows[0].starts_with("tog-toolchain.toml stale: "),
            "{rows:?}"
        );
        assert!(rows[0].contains(".python-version version"), "{rows:?}");
        assert!(
            rows[0].contains("recorded 3.12.14, now 3.13.15"),
            "{rows:?}"
        );
        assert!(
            rows[0].ends_with("run 'tog update --toolchain python'"),
            "{rows:?}"
        );
        fs::write(dir.join(".python-version"), "3.12.14\n").unwrap();

        // A toolchain input that does not parse is stale and named, never
        // an error that hides the whole status.
        fs::write(
            dir.join("pyproject.toml"),
            "[project]\nrequires-python = 3\n",
        )
        .unwrap();
        let verdict = &status(platform, dir).unwrap()[0].state;
        let State::Changed(rows) = verdict else {
            panic!("a malformed toolchain input did not report the lock: {verdict:?}");
        };
        assert!(
            rows[0].starts_with("tog-toolchain.toml stale: pyproject.toml: "),
            "{rows:?}"
        );
        fs::remove_file(dir.join("pyproject.toml")).unwrap();

        // A committed lock that describes some other ecosystem, but has no
        // section for this one.
        let bytes = fs::read(dir.join(LOCK_PATH)).unwrap();
        let root = ProjectRoot::open(dir).unwrap();
        let go = tailors::by_id("go").unwrap();
        let go_catalog = go.toolchain_catalog().unwrap();
        let go_rows = input::discover(&root, "go").unwrap();
        let go_bundle = crate::kernel::toolchain::select_for(&go_catalog, "go", &go_rows).unwrap();
        let mut other = ToolchainLock::new(env!("CARGO_PKG_VERSION"));
        other.set_ecosystem("go", go_bundle, &go_rows).unwrap();
        fs::write(dir.join(LOCK_PATH), other.canonical_bytes()).unwrap();
        assert_eq!(
            status(platform, dir).unwrap()[0].state,
            State::Changed(vec![
                "tog-toolchain.toml (no [toolchain.python] section; run 'tog update --toolchain python')"
                    .into()
            ])
        );

        // A projection built from a different bundle than the lock names.
        fs::write(dir.join(LOCK_PATH), &bytes).unwrap();
        let closure = dir.join(".tog/closures/python.json");
        let mut record: Value = serde_json::from_slice(&fs::read(&closure).unwrap()).unwrap();
        let recorded = record["body"]["toolchain"]["bundle_id"].clone();
        record["body"]["toolchain"]["bundle_id"] = json!("sha256:".to_string() + &"0".repeat(64));
        fs::write(&closure, serde_json::to_vec_pretty(&record).unwrap()).unwrap();
        assert_eq!(
            status(platform, dir).unwrap()[0].state,
            State::Changed(vec![
                "tog-toolchain.toml (toolchain changed since the last sync; run 'tog')".into()
            ])
        );

        // A closure written before the lock existed cannot be compared at
        // all, which is the answer every unrecorded field gets.
        record["body"]["toolchain"] = Value::Null;
        record["body"].as_object_mut().unwrap().remove("toolchain");
        fs::write(&closure, serde_json::to_vec_pretty(&record).unwrap()).unwrap();
        assert_eq!(
            status(platform, dir).unwrap()[0].state,
            State::Unchecked("toolchain not recorded by this sync; run 'tog' once".into())
        );
        assert!(!status(platform, dir).unwrap()[0].is_synced());

        // No lock at all: a synced closure with nothing to stand on.
        record["body"]["toolchain"] = json!({"bundle_id": recorded});
        fs::write(&closure, serde_json::to_vec_pretty(&record).unwrap()).unwrap();
        fs::remove_file(dir.join(LOCK_PATH)).unwrap();
        assert_eq!(
            status(platform, dir).unwrap()[0].state,
            State::Changed(vec![
                "tog-toolchain.toml (missing; run 'tog' to create it)".into()
            ])
        );
        // The lock line is printed as written: its next step is not always
        // the bare `tog`, so the dependency-input sentence is not appended.
        let rows = status(platform, dir).unwrap();
        let line = render_status(dir, &rows, false).unwrap();
        assert!(
            line.contains("changed     tog-toolchain.toml (missing; run 'tog' to create it)\n"),
            "{line}"
        );
        let value: Value = serde_json::from_str(&render_status(dir, &rows, true).unwrap()).unwrap();
        assert_eq!(value["ecosystems"][0]["state"], "changed");
        assert_eq!(
            value["ecosystems"][0]["detail"][0],
            "tog-toolchain.toml (missing; run 'tog' to create it)"
        );
    }

    #[test]
    fn a_refusing_lock_verdict_outranks_a_changed_closure_input() {
        let temp = TempDir::named("status-lock-order");
        let platform = Platform::host().unwrap();
        let dir = &temp.0;
        fs::write(dir.join("requirements.txt"), "six==1.17.0\n").unwrap();
        fs::write(dir.join(".python-version"), "3.12.14\n").unwrap();
        let env = dir.join("env-object");
        fs::create_dir_all(env.join("bin")).unwrap();
        std::os::unix::fs::symlink(&env, dir.join(".venv")).unwrap();
        let requirements = sha256_file(&dir.join("requirements.txt")).unwrap();
        let pin = sha256_file(&dir.join(".python-version")).unwrap();
        // The closure also records `.python-version` as a dependency input,
        // so moving it trips both the closure and the lock.
        write_closure(
            dir,
            "python",
            platform.triple(),
            json!({"env_object": env, "python": {"version": "3.12.14"},
                   "plan": {"packages": []},
                   "inputs": [{"path": "requirements.txt", "sha256": requirements},
                              {"path": ".python-version", "sha256": pin}]}),
        );
        assert_eq!(status(platform, dir).unwrap()[0].state, State::Synced);
        fs::write(dir.join(".python-version"), "3.13.15\n").unwrap();
        // "run 'tog'" would only reach the stale-lock refusal, so the
        // lock's line, with the verb that moves it, is the one reported.
        let State::Changed(rows) = &status(platform, dir).unwrap()[0].state else {
            panic!("a moved toolchain source did not report the lock");
        };
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert!(
            rows[0].starts_with("tog-toolchain.toml stale: "),
            "{rows:?}"
        );
        assert!(
            rows[0].ends_with("run 'tog update --toolchain python'"),
            "{rows:?}"
        );
        // With the lock removed, nothing refuses: a plain sync re-reads the
        // pin and creates the lock, so the closure's own verdict is reported.
        fs::remove_file(dir.join(LOCK_PATH)).unwrap();
        let State::Changed(rows) = &status(platform, dir).unwrap()[0].state else {
            panic!("a moved input did not report the closure");
        };
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert!(rows[0].starts_with(".python-version"), "{rows:?}");
    }

    #[test]
    fn status_validates_node_forest_and_workspace_links() {
        let temp = TempDir::named("node-projection");
        let platform = Platform::host().unwrap();
        let project = &temp.0;
        fs::write(project.join("package.json"), "{}\n").unwrap();
        let store = project.join("store");
        let env = store.join("objects/env-id");
        fs::create_dir_all(env.join("node_modules")).unwrap();
        fs::create_dir_all(project.join("packages/lib")).unwrap();
        let project_key = hex::encode(Sha256::digest(
            project.canonicalize().unwrap().to_string_lossy().as_bytes(),
        ));
        let projection = project
            .join("forests")
            .join(&project_key[..32])
            .join("a".repeat(32));
        let workspace_env = projection.join("workspaces/packages%2Flib/node_modules");
        fs::create_dir_all(&workspace_env).unwrap();
        fs::create_dir_all(projection.join("node_modules")).unwrap();
        std::os::unix::fs::symlink(
            projection.join("node_modules"),
            project.join("node_modules"),
        )
        .unwrap();
        std::os::unix::fs::symlink(&workspace_env, project.join("packages/lib/node_modules"))
            .unwrap();
        write_closure(
            project,
            "node",
            platform.triple(),
            json!({
                "env_object": env,
                "projection_schema": "node-forest/2",
                "projection_id": "a".repeat(32),
                "workspaces": ["packages/lib"],
                "inputs": [{"path": "package.json", "sha256": sha256_file(&project.join("package.json")).unwrap()}]
            }),
        );
        let rows = status(platform, project).unwrap();
        assert_eq!(rows[0].state, State::Synced);

        fs::remove_file(project.join("node_modules")).unwrap();
        std::os::unix::fs::symlink(&env, project.join("node_modules")).unwrap();
        let rows = status(platform, project).unwrap();
        assert_eq!(
            rows[0].state,
            State::ProjectionMissing("node_modules".into())
        );

        fs::remove_file(project.join("node_modules")).unwrap();
        std::os::unix::fs::symlink(
            projection.join("node_modules"),
            project.join("node_modules"),
        )
        .unwrap();
        fs::remove_file(project.join("packages/lib/node_modules")).unwrap();
        let rows = status(platform, project).unwrap();
        assert_eq!(
            rows[0].state,
            State::ProjectionMissing("workspace node_modules".into())
        );

        // An `npm install` replaces the projection symlink with a real
        // directory. That is the common way a synced project stops being
        // synced, so status names the cause rather than reporting the
        // generic missing projection.
        fs::remove_file(project.join("node_modules")).unwrap();
        fs::create_dir_all(project.join("node_modules/is-odd")).unwrap();
        let rows = status(platform, project).unwrap();
        let State::ProjectionMissing(detail) = &rows[0].state else {
            panic!(
                "a real node_modules was not reported missing: {:?}",
                rows[0]
            );
        };
        assert!(detail.contains("a real directory"), "{detail}");
        assert!(detail.contains("install tool"), "{detail}");
        let line = render_status(project, &rows, false).unwrap();
        assert!(line.contains("run 'tog'"), "{line}");
    }

    #[test]
    fn status_reports_missing_non_python_toolchain_objects() {
        let host = Platform::host().unwrap().triple();
        let cases = [
            (
                "go",
                "go.mod",
                "go_object",
                "modcache_object",
                "go_object object",
            ),
            (
                "ruby",
                "Gemfile",
                "ruby_object",
                "gems_object",
                "ruby_object object",
            ),
            (
                "elixir",
                "mix.exs",
                "beam_object",
                "deps_object",
                "beam_object object",
            ),
            (
                "dotnet",
                "app.csproj",
                "sdk_object",
                "packages_object",
                "sdk_object object",
            ),
        ];
        for (ecosystem, marker, first, second, expected) in cases {
            let temp = TempDir::named(&format!("missing-{ecosystem}"));
            fs::write(temp.0.join(marker), "").unwrap();
            let mut body = json!({"inputs": []});
            body[first] = json!({"path": temp.0.join("missing/first")});
            body[second] = json!({"path": temp.0.join("missing/second")});
            write_closure(&temp.0, ecosystem, host, body);
            let rows = status(Platform::host().unwrap(), &temp.0).unwrap();
            let row = rows.iter().find(|row| row.ecosystem == ecosystem).unwrap();
            assert_eq!(row.state, State::ProjectionMissing(expected.into()));
        }
    }

    /// In a bare directory with a fresh store, `doctor` leaves no write
    /// probe behind and reports that there is no project.
    /// `doctor` the way `tog doctor` calls it: the configured store, opened
    /// and leased, or the error that stopped it.
    fn doctor_of_configured_store(dir: &Path) -> Vec<Check> {
        let opened = Store::open().and_then(|store| {
            let activity = store.try_activity_shared()?;
            Ok((store, activity))
        });
        doctor(
            dir,
            opened
                .as_ref()
                .map(|(store, activity)| (store, activity.as_ref())),
        )
    }

    /// A refusal that becomes a doctor row keeps its fix, and one for a
    /// store the bare command would not select names that store.
    #[test]
    fn a_refused_store_row_keeps_the_typed_fix() {
        let temp = TempDir::named("doctor-refused");
        let root = temp.0.join("store");
        fs::create_dir_all(root.join("objects")).unwrap();
        let error = Store::open_at(&root).unwrap_err();
        let mut checks = Vec::new();
        store_checks(Err(&error), &mut checks);
        assert_eq!(checks.len(), 1);
        assert_eq!(checks[0].level, Level::Fail);
        let detail = &checks[0].detail;
        assert!(detail.contains("has no format marker"), "{detail}");
        let fix = crate::kernel::store::refusal_fix(&error).unwrap();
        assert!(fix.starts_with("TOG_STORE="), "{fix}");
        assert!(detail.ends_with(&format!("; run '{fix}'")), "{detail}");

        // Any other failure reads as before.
        let mut checks = Vec::new();
        store_checks(Err(&io::Error::other("create the store")), &mut checks);
        assert_eq!(checks[0].detail, "cannot create the store");
    }

    /// The store doctor reads is the one it was handed under a lease: a
    /// lease on another store is a failing row, and nothing is probed.
    #[test]
    fn doctor_reads_no_store_without_its_own_lease() {
        let temp = TempDir::named("doctor-lease");
        let store = Store::open_at(&temp.0.join("store")).unwrap();
        let other = Store::open_at(&temp.0.join("other")).unwrap();
        let foreign = other
            .activity(crate::kernel::activity::ActivityMode::Shared)
            .unwrap();
        let mut checks = Vec::new();
        store_checks(Ok((&store, Some(&foreign))), &mut checks);
        assert_eq!(
            checks.len(),
            1,
            "{:?}",
            checks.iter().map(|c| &c.detail).collect::<Vec<_>>()
        );
        assert_eq!(checks[0].level, Level::Fail);

        let own = store
            .activity(crate::kernel::activity::ActivityMode::Shared)
            .unwrap();
        let mut checks = Vec::new();
        store_checks(Ok((&store, Some(&own))), &mut checks);
        let names: Vec<&str> = checks.iter().map(|check| check.name).collect();
        assert_eq!(names, ["store", "disk", "toolchains"]);

        // No lease because the store is busy: one warning, nothing read.
        let mut checks = Vec::new();
        store_checks(Ok((&store, None)), &mut checks);
        assert_eq!(checks.len(), 1);
        assert_eq!(checks[0].name, "store");
        assert_eq!(checks[0].level, Level::Warn);
        assert!(
            checks[0].detail.contains("a Tog job is using the store at"),
            "{}",
            checks[0].detail
        );
        assert!(fs::read_dir(store.root.join("tmp"))
            .unwrap()
            .flatten()
            .all(|entry| !entry.file_name().to_string_lossy().starts_with(".doctor-")));
    }

    #[test]
    fn doctor_cleans_up_its_probe_and_finds_no_project_in_a_bare_dir() {
        // Process-global test state follows env -> store -> attribution (see the comment on `commands::sync`'s
        // failed_tailor_sync test). `doctor`'s policy check reads
        // TOG_POLICY and $HOME, so the env lock is taken first.
        let _env = crate::kernel::policy::test_env_lock();
        let _lock = crate::kernel::store::STORE_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let temp = TempDir::named("doctor");
        let store = temp.0.join("store");
        let old_store = std::env::var_os("TOG_STORE");
        std::env::set_var("TOG_STORE", &store);
        let checks = doctor_of_configured_store(&temp.0);
        match old_store {
            Some(value) => std::env::set_var("TOG_STORE", value),
            None => std::env::remove_var("TOG_STORE"),
        }
        assert!(fs::read_dir(store.join("tmp"))
            .unwrap()
            .flatten()
            .all(|entry| !entry.file_name().to_string_lossy().starts_with(".doctor-")));
        let project = checks.iter().find(|check| check.name == "project").unwrap();
        assert!(project.detail.contains("no project in"));
    }

    /// Characterization: `doctor`'s value is the order and the wording of
    /// what it prints, so pin both.
    #[test]
    fn doctor_check_order_and_wording_are_fixed() {
        // Same env -> store order as the bare-dir test above.
        let _env = crate::kernel::policy::test_env_lock();
        let _lock = crate::kernel::store::STORE_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let temp = TempDir::named("doctor-order");
        let store = temp.0.join("store");
        fs::write(temp.0.join("go.mod"), "module example.com/m\n\ngo 1.27.0\n").unwrap();
        fs::create_dir_all(temp.0.join(".tog")).unwrap();
        fs::write(temp.0.join(".tog/policy.toml"), "").unwrap();
        let old_store = std::env::var_os("TOG_STORE");
        std::env::set_var("TOG_STORE", &store);
        let checks = doctor_of_configured_store(&temp.0);
        match old_store {
            Some(value) => std::env::set_var("TOG_STORE", value),
            None => std::env::remove_var("TOG_STORE"),
        }

        let names: Vec<&str> = checks.iter().map(|check| check.name).collect();
        // The platform check is first, then the store block in this order;
        // the per-tailor probes follow it; the sandbox and C-toolchain probes
        // close the platform section; policy and project are always last.
        assert_eq!(
            &names[..4],
            &["platform", "store", "disk", "toolchains"],
            "{names:?}"
        );
        assert_eq!(
            &names[names.len() - 2..],
            &["policy", "project"],
            "{names:?}"
        );
        let sandbox_at = names.iter().position(|name| *name == "sandbox").unwrap();
        assert_eq!(names[sandbox_at + 1], "c-toolchain", "{names:?}");
        assert_eq!(names.len() - 2, sandbox_at + 2, "{names:?}");
        assert!(names[4..sandbox_at].contains(&"go-toolchain"), "{names:?}");

        let detail = |name: &str| {
            checks
                .iter()
                .find(|check| check.name == name)
                .unwrap_or_else(|| panic!("no {name} check"))
        };
        assert_eq!(detail("platform").level, Level::Ok);
        assert_eq!(
            detail("platform").detail,
            Platform::host().unwrap().triple()
        );
        assert_eq!(detail("store").level, Level::Ok);
        assert_eq!(
            detail("store").detail,
            format!(
                "{} (0 objects, 0 cached artifacts)",
                store.canonicalize().unwrap().display()
            )
        );
        assert!(
            detail("disk").detail.contains("GiB free under the store"),
            "{}",
            detail("disk").detail
        );
        assert_eq!(
            detail("toolchains").detail,
            "none realized yet; the first 'tog' downloads what the project needs"
        );
        assert_eq!(detail("policy").level, Level::Ok);
        assert!(
            detail("policy").detail.ends_with(".tog/policy.toml"),
            "{}",
            detail("policy").detail
        );
        assert_eq!(detail("project").level, Level::Ok);
        assert_eq!(
            detail("project").detail,
            "go found; not synced yet: go (run 'tog')"
        );

        let text = render_doctor(&checks, false).unwrap();
        assert!(
            text.lines().next().unwrap().starts_with("ok    platform"),
            "{text}"
        );
        // The project check is the last line of the report; a host whose
        // sandbox or C toolchain fails appends a summary after it.
        let last_check = text
            .lines()
            .rfind(|line| {
                line.starts_with("ok  ") || line.starts_with("warn") || line.starts_with("fail")
            })
            .unwrap();
        assert!(last_check.ends_with(&detail("project").detail), "{text}");

        // JSON carries every check, in the same order as the text.
        let value: Value = serde_json::from_str(&render_doctor(&checks, true).unwrap()).unwrap();
        let json_names: Vec<&str> = value["checks"]
            .as_array()
            .unwrap()
            .iter()
            .map(|check| check["name"].as_str().unwrap())
            .collect();
        assert_eq!(json_names, names);

        // The three level words are the ones CLI.md documents, lowercase.
        let failing = vec![
            check("platform", Level::Ok, "ok"),
            check("sandbox", Level::Warn, "warn"),
            check("store", Level::Fail, "unwritable"),
        ];
        let text = render_doctor(&failing, false).unwrap();
        assert!(text.contains("fail  store     unwritable"), "{text}");
        assert!(!text.contains("FAIL"), "{text}");
        assert!(text.ends_with("1 check failed.\n"), "{text}");
    }
}

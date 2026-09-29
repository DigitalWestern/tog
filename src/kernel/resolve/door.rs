//! The confined mode of the resolution door: one tool run in isolation
//! against a snapshot of the project, reaching the network only through a
//! proxy session, and published all or nothing.
//!
//! In order: preflight (the isolation tier, the signing key, the forced
//! settings), hold the targets (which recovers an interrupted publication
//! first), snapshot, open the proxy session on a private Unix socket, run
//! the tool through the relay until its whole tree has stopped, finish the
//! session, copy the declared outputs and check them, record the session's
//! exceptions on the owner thread, commit and root the ledger, produce the
//! receipt, publish. Any failure before publication leaves the project as
//! it was; the ledger this run rooted is taken back.

use super::confine::{self, ConfinedOutcome, ConfinedRun, ForcedInputs, SocketScan, Stdout};
use super::ledger::{self, Diagnostics, LedgerObjects};
use super::outputs::{Forbidden, OutputFile, Outputs};
use super::proxy::Proxy;
use super::relay::{self, ToolStatus};
use super::routes::{Permitted, ProxyAddress, Route};
use super::session::{Fact, Intercept, Mode as Network, SessionConfig, SessionReport};
use super::snapshot::{EntryState, PathGlob, Snapshot, SnapshotSpec};
use super::transaction::{HoldSpec, Transaction};
use super::{DelegateReport, DelegateSpec, DelegateStdio, DoorKind, ResolutionDoor};
use crate::kernel::activity::StoreActivity;
use crate::kernel::fsroot::ProjectRoot;
use crate::kernel::policy::{self, Policy};
use crate::kernel::store::Store;
use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::os::unix::process::ExitStatusExt;
use std::path::{Component, Path, PathBuf};
use std::process::ExitStatus;

/// Makes the receipt from what the run established. `Ok(None)` leaves the
/// held receipt as it was.
pub type ReceiptProducer<'a> =
    Box<dyn FnOnce(&PublishFacts<'_>) -> io::Result<Option<Vec<u8>>> + 'a>;

/// Points the tool at the session: arguments, variables, config files.
pub type Wirer<'a> = Box<dyn FnOnce(&Wire<'_>) -> io::Result<Wiring> + 'a>;

/// Where a confined run's accepted outputs go.
pub enum Target<'a> {
    /// The lock root is a project: the outputs (and the receipt, when a
    /// producer is given) are published through a transaction under the
    /// project lock, and the ledger is rooted in the project's root record.
    Project {
        receipt: Option<ReceiptProducer<'a>>,
    },
    /// The lock root is not a project (a planner step, a `tog x` cache
    /// stage, an unpacked sdist): no transaction, no receipt. Accepted
    /// outputs are written back into the lock root one file at a time, and
    /// the ledger is committed but not rooted; the caller roots the ids in
    /// the report before its store lease ends.
    Detached,
}

/// What a wiring callback sees.
pub struct Wire<'w> {
    /// The session as the tool sees it (the relay's fixed address).
    pub address: &'w ProxyAddress,
    /// The run's scratch directory, at the same path inside the sandbox.
    /// `HOME`, `TMPDIR` and `XDG_CACHE_HOME` default below it.
    pub scratch: &'w Path,
    /// The spec's arguments.
    pub args: &'w [OsString],
    /// The tool's forced arguments. Each must appear in `Wiring::args`,
    /// wherever the tool's grammar reads it.
    pub forced_args: &'w [OsString],
}

/// How a tool is pointed at its session.
#[derive(Debug, Default)]
pub struct Wiring {
    /// Every argument after the program, forced ones included.
    pub args: Vec<OsString>,
    /// Variables set on top of the spec's.
    pub env: Vec<(OsString, OsString)>,
    /// Config files written into the scratch directory before the run:
    /// paths relative to it, created 0600.
    pub files: Vec<(PathBuf, Vec<u8>)>,
    /// Further git settings (`http.proxy`, `url.<base>.insteadOf`); the
    /// forced ones still have the last word.
    pub extra_git: Vec<(String, String)>,
}

/// Everything a confined run needs beyond the tool invocation itself.
pub struct ConfinedSpec<'a> {
    /// `[a-z0-9-]+`: names the ledger, the receipt and the journal.
    pub ecosystem: &'a str,
    /// The tool's row in the forced-settings table.
    pub tool: &'a str,
    /// The tool as messages name it, and why it needs isolation ("can run
    /// programs a project's .npmrc names").
    pub name: &'a str,
    pub why: &'a str,
    pub forced: ForcedInputs<'a>,
    /// Files the tool may write, relative to the lock root.
    pub outputs: Vec<PathBuf>,
    /// Paths under the lock root the tool may change; discarded.
    pub scratch_outputs: Vec<PathGlob>,
    /// Paths under each snapshot root that are neither copied nor diffed.
    pub exclude: Vec<PathGlob>,
    /// Project-side trees outside the lock root the tool reads.
    pub extra_roots: Vec<PathBuf>,
    /// Store objects the tool runs from, bound read-only.
    pub store_reads: Vec<PathBuf>,
    pub routes: Vec<Route>,
    pub network: Network,
    /// `None` passes the spec's arguments with the forced ones appended
    /// (before a `--`, if there is one).
    pub wire: Option<Wirer<'a>>,
    pub target: Target<'a>,
    /// `None` is the process's proxy.
    pub proxy: Option<&'a Proxy>,
    pub permitted: Permitted,
    /// `None` is the process policy.
    pub policy: Option<Policy>,
}

impl<'a> ConfinedSpec<'a> {
    /// A project run with no receipt, online, through the process proxy,
    /// to the compiled registry set, under the process policy.
    pub fn new(ecosystem: &'a str, tool: &'a str, why: &'a str) -> Self {
        Self {
            ecosystem,
            tool,
            name: tool,
            why,
            forced: ForcedInputs::default(),
            outputs: Vec::new(),
            scratch_outputs: Vec::new(),
            exclude: Vec::new(),
            extra_roots: Vec::new(),
            store_reads: Vec::new(),
            routes: Vec::new(),
            network: Network::Online,
            wire: None,
            target: Target::Project { receipt: None },
            proxy: None,
            permitted: Permitted::compiled(),
            policy: None,
        }
    }
}

/// What a receipt producer is given.
pub struct PublishFacts<'f> {
    pub ecosystem: &'f str,
    pub door: DoorKind,
    /// The accepted outputs, with their digests.
    pub outputs: &'f [OutputFile],
    pub ledger: &'f LedgerObjects,
    /// The sha256 of the portable ledger's bytes.
    pub ledger_sha256: &'f str,
    /// `confined` or `isolated`, and the engine.
    pub isolation: &'static str,
    pub engine: &'static str,
    /// The exceptions this run recorded.
    pub exceptions: &'f [Fact],
    snapshot: &'f Snapshot,
}

impl PublishFacts<'_> {
    /// The pre-run sha256 of a regular file under the lock root (a
    /// manifest the receipt vouches for), `None` when it was not one.
    pub fn input_digest(&self, relative: &Path) -> Option<[u8; 32]> {
        let real = self.snapshot.lock_root().real.join(relative);
        match self.snapshot.baseline(&real) {
            Some(EntryState::File { sha256, .. }) => Some(*sha256),
            _ => None,
        }
    }
}

/// The confined run of `spec` through `door`.
pub(super) fn run(
    door: &mut ResolutionDoor<'_>,
    spec: DelegateSpec,
    mut confined: ConfinedSpec<'_>,
) -> io::Result<DelegateReport> {
    let (store, activity) = (door.store, door.activity);
    let lock_root = spec.lock_root.as_deref().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "{} runs confined only in a lock root, and none was given",
                confined.name
            ),
        )
    })?;
    let lock_root = fs::canonicalize(lock_root)?;
    let policy = confined.policy.take().unwrap_or_else(policy::effective);
    let forced_args = preflight(activity, &confined, &policy, &lock_root)?;
    let target = std::mem::replace(&mut confined.target, Target::Detached);
    let (mut hold, receipt) = match target {
        Target::Project { receipt } => {
            let root = ProjectRoot::open(&lock_root)?;
            let again = root.try_clone()?;
            let spec = HoldSpec {
                ecosystem: confined.ecosystem,
                outputs: &confined.outputs,
                receipt: receipt.is_some(),
            };
            let tx = Transaction::hold(store, activity, root, &spec)?;
            (Some((tx, again)), receipt)
        }
        Target::Detached => (None, None),
    };
    let snapshot = Snapshot::build(
        store,
        activity,
        &SnapshotSpec {
            lock_root: &lock_root,
            extra_roots: &confined.extra_roots,
            exclude: &confined.exclude,
        },
    )?;
    let ran = run_tool(door, &spec, &mut confined, &policy, &snapshot, &forced_args)?;
    let status = exit_status(ran.outcome.status);
    if let Some(failure) = ran.session.facts.failure() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{} ({status}): {failure}; nothing was published",
                confined.name
            ),
        ));
    }
    if !status.success() {
        // The call site words a failing tool, as it does for `Legacy`.
        // Nothing was published and no ledger is kept.
        return Ok(report(status, ran.outcome, None));
    }
    let outputs = check_outputs(store, activity, &confined, &snapshot, &ran)?;
    let facts = record_facts(&confined, &policy, &ran)?;
    let diagnostics = diagnostics(
        store,
        door,
        &confined,
        &ran.outcome,
        ran.session.diagnostics,
    );
    let ledger_sha256 = ran.session.ledger.sha256();
    let objects = ledger::commit(store, activity, &ran.session.ledger, &diagnostics)?;
    let publish = PublishFacts {
        ecosystem: confined.ecosystem,
        door: door.kind,
        outputs: outputs.files(),
        ledger: &objects,
        ledger_sha256: &ledger_sha256,
        isolation: ran.outcome.tier.isolation(),
        engine: ran.outcome.tier.engine.name(),
        exceptions: &facts,
        snapshot: &snapshot,
    };
    match hold.take() {
        Some((tx, again)) => {
            publish_project(store, activity, tx, &again, &outputs, &publish, receipt)?
        }
        None => write_back(&lock_root, &outputs)?,
    }
    Ok(report(status, ran.outcome, Some(objects)))
}

/// Step 1: refuse before anything is held or copied.
fn preflight(
    activity: &StoreActivity,
    confined: &ConfinedSpec<'_>,
    policy: &Policy,
    lock_root: &Path,
) -> io::Result<Vec<OsString>> {
    let unconfined_denied = policy::denied(policy, policy::UNCONFINED_RESOLUTION);
    let (offers, missing) = confine::probe_tiers(activity);
    confine::choose_tier(
        &offers,
        &missing,
        unconfined_denied,
        confined.name,
        confined.why,
    )?;
    let mut roots = vec![lock_root.to_path_buf()];
    roots.extend(confined.extra_roots.iter().cloned());
    confine::refuse_key_in_snapshot_roots(&roots)?;
    Ok(confine::forced_settings(confined.tool, &confined.forced, &[])?.args)
}

/// What the tool run and its session produced.
struct Ran {
    outcome: ConfinedOutcome,
    session: SessionReport,
    token: String,
    advertised: String,
}

/// Steps 4 and 5: open the session, wire the tool to it, run it until its
/// whole tree has stopped, then finish the session.
fn run_tool(
    door: &ResolutionDoor<'_>,
    spec: &DelegateSpec,
    confined: &mut ConfinedSpec<'_>,
    policy: &Policy,
    snapshot: &Snapshot,
    forced_args: &[OsString],
) -> io::Result<Ran> {
    let proxy = match confined.proxy {
        Some(proxy) => proxy,
        None => super::proxy::proxy()?,
    };
    let mut session = proxy.open_session(SessionConfig {
        ecosystem: confined.ecosystem.to_string(),
        door: door.kind.as_str().to_string(),
        routes: confined.routes.clone(),
        intercept: Intercept::RefuseVisibly,
        policy: policy.clone(),
        mode: confined.network,
        store: door.store.clone(),
        activity: door.activity.clone(),
        permitted: confined.permitted.clone(),
    })?;
    let dir = SessionDir::create()?;
    let advertised = relay::LISTEN_ADDRESS
        .parse()
        .map_err(|error| io::Error::other(format!("the relay address: {error}")))?;
    let address = session.listen_unix(&dir.socket, advertised)?;
    let invocation = invocation(spec, confined, &address, snapshot, forced_args)?;
    let executable = relay_executable()?;
    let unconfined_denied = policy::denied(policy, policy::UNCONFINED_RESOLUTION);
    let outcome = confine::confined_run(
        door.store,
        door.activity,
        &ConfinedRun {
            tool: confined.name,
            why: confined.why,
            unconfined_denied,
            snapshot,
            proxy_socket: &dir.socket,
            executable: &executable,
            argv: &invocation.argv,
            cwd: &snapshot.lock_root().real,
            env: &invocation.env,
            read_roots: &confined.store_reads,
            stdout: match spec.stdio {
                DelegateStdio::Inherit => Stdout::Inherit,
                DelegateStdio::Capture => Stdout::Capture,
            },
            socket_scan: socket_scan(),
        },
    );
    let token = session.token().to_string();
    let report = session.finish();
    drop(dir);
    Ok(Ran {
        outcome: outcome?,
        session: report,
        token,
        advertised: advertised.to_string(),
    })
}

/// The tool's argv and whole environment.
struct Invocation {
    argv: Vec<OsString>,
    env: Vec<(OsString, OsString)>,
}

fn invocation(
    spec: &DelegateSpec,
    confined: &mut ConfinedSpec<'_>,
    address: &ProxyAddress,
    snapshot: &Snapshot,
    forced_args: &[OsString],
) -> io::Result<Invocation> {
    let wiring = match confined.wire.take() {
        Some(wire) => wire(&Wire {
            address,
            scratch: snapshot.scratch(),
            args: &spec.args,
            forced_args,
        })?,
        None => Wiring {
            args: with_forced(&spec.args, forced_args),
            ..Wiring::default()
        },
    };
    for forced in forced_args {
        if !wiring.args.contains(forced) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "the wiring for {} dropped the forced argument {}",
                    confined.name,
                    forced.to_string_lossy()
                ),
            ));
        }
    }
    for (relative, bytes) in &wiring.files {
        write_scratch_file(snapshot.scratch(), relative, bytes)?;
    }
    let forced = confine::forced_settings(confined.tool, &confined.forced, &wiring.extra_git)?;
    // The spec's variables over nothing: a confined tool never sees tog's
    // own environment.
    let mut env: Vec<(OsString, OsString)> = spec
        .env
        .iter()
        .filter_map(|(key, value)| value.as_ref().map(|value| (key.clone(), value.clone())))
        .collect();
    for (key, value) in wiring.env {
        env.retain(|(existing, _)| *existing != key);
        env.push((key, value));
    }
    forced.apply(&mut env);
    let mut argv = vec![spec.program.clone().into_os_string()];
    argv.extend(wiring.args);
    Ok(Invocation { argv, env })
}

/// `args` with `forced` appended, before the first `--`.
fn with_forced(args: &[OsString], forced: &[OsString]) -> Vec<OsString> {
    let split = args
        .iter()
        .position(|arg| arg == "--")
        .unwrap_or(args.len());
    let mut all = args[..split].to_vec();
    all.extend(forced.iter().cloned());
    all.extend(args[split..].iter().cloned());
    all
}

fn write_scratch_file(scratch: &Path, relative: &Path, bytes: &[u8]) -> io::Result<()> {
    if relative
        .components()
        .any(|part| !matches!(part, Component::Normal(_)))
        || relative.as_os_str().is_empty()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "the config file {} must be a plain path inside the scratch directory",
                relative.display()
            ),
        ));
    }
    let path = scratch.join(relative);
    if let Some(parent) = path.parent() {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)?;
    }
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)?;
    io::Write::write_all(&mut file, bytes)
}

/// Step 5: the diff holds only declared outputs and scratch, and no output
/// carries the session's token or address.
fn check_outputs(
    store: &Store,
    activity: &StoreActivity,
    confined: &ConfinedSpec<'_>,
    snapshot: &Snapshot,
    ran: &Ran,
) -> io::Result<Outputs> {
    let changes = snapshot.diff()?;
    let classified = snapshot.classify(&changes, &confined.outputs, &confined.scratch_outputs)?;
    Outputs::copy(
        store,
        activity,
        snapshot,
        &classified.outputs,
        &[
            Forbidden::new("the proxy session token", ran.token.as_bytes()),
            Forbidden::new("the proxy address", ran.advertised.as_bytes()),
        ],
    )
}

/// Record the run's exceptions into the attribution on this thread, the
/// one that owns it. A denied kind fails the door.
fn record_facts(confined: &ConfinedSpec<'_>, policy: &Policy, ran: &Ran) -> io::Result<Vec<Fact>> {
    let tier = ran.outcome.tier;
    let mut facts: Vec<Fact> = tier
        .exceptions()
        .iter()
        .map(|kind| Fact {
            kind,
            subject: confined.name.to_string(),
            detail: format!(
                "ran in {}, which isolates files and processes but cannot fence the network \
                 to tog's proxy",
                tier.engine.name()
            ),
        })
        .collect();
    facts.extend(ran.session.facts.exceptions.iter().cloned());
    for fact in &facts {
        policy::record_with(policy, fact.kind, &fact.subject, &fact.detail)?;
    }
    Ok(facts)
}

/// The run-local sidecar: the session's, plus the isolation and the exec
/// log.
fn diagnostics(
    store: &Store,
    door: &ResolutionDoor<'_>,
    confined: &ConfinedSpec<'_>,
    outcome: &ConfinedOutcome,
    mut diagnostics: Diagnostics,
) -> Diagnostics {
    diagnostics.engine = Some(outcome.tier.engine.name().to_string());
    diagnostics.platform = Some(door.platform.triple().to_string());
    let objects = store.root.join("objects");
    diagnostics.tools = confined
        .store_reads
        .iter()
        .filter_map(|path| path.strip_prefix(&objects).ok())
        .filter_map(|rest| rest.components().next())
        .map(|id| id.as_os_str().to_string_lossy().into_owned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let execs: Vec<serde_json::Value> = outcome
        .execs
        .iter()
        .map(|exec| serde_json::json!({"pid": exec.pid, "parent": exec.parent, "path": exec.path}))
        .collect();
    diagnostics
        .extra
        .insert("isolation".into(), outcome.tier.isolation().into());
    diagnostics.extra.insert("execs".into(), execs.into());
    diagnostics
        .extra
        .insert("killed".into(), (outcome.killed as u64).into());
    diagnostics
}

/// Steps 6 to 10 for a project: root the ledger under the held lock, make
/// the receipt, publish. On any failure the ledger ids this run added to
/// the root record are taken back.
fn publish_project(
    store: &Store,
    activity: &StoreActivity,
    tx: Transaction<'_>,
    again: &ProjectRoot,
    outputs: &Outputs,
    facts: &PublishFacts<'_>,
    receipt: Option<ReceiptProducer<'_>>,
) -> io::Result<()> {
    let ids = BTreeSet::from([
        facts.ledger.ledger.clone(),
        facts.ledger.diagnostics.clone(),
    ]);
    let before = store.rooted_objects_locked(activity, tx.root(), tx.project_lock())?;
    let added: BTreeSet<String> = ids.difference(&before).cloned().collect();
    let rooted = store.register_root_parts_with_project_lock(
        activity,
        tx.root(),
        ids,
        BTreeSet::new(),
        tx.project_lock(),
    );
    if let Err(error) = rooted {
        return Err(unroot_after(store, activity, &tx, &added, error));
    }
    let bytes = match receipt.map(|produce| produce(facts)).transpose() {
        Ok(bytes) => bytes.flatten(),
        Err(error) => return Err(unroot_after(store, activity, &tx, &added, error)),
    };
    if let Err(error) = tx.publish(outputs, bytes.as_deref()) {
        // The transaction undid itself and released its lock; take it
        // again to take the ledger back.
        let lock = store.project_lock_in(again)?;
        store.unroot_objects_locked(activity, again, &added, &lock)?;
        return Err(error);
    }
    Ok(())
}

/// Take back the ledger ids this run rooted, then report `error`. The
/// transaction is abandoned when it drops.
fn unroot_after(
    store: &Store,
    activity: &StoreActivity,
    tx: &Transaction<'_>,
    added: &BTreeSet<String>,
    error: io::Error,
) -> io::Error {
    match store.unroot_objects_locked(activity, tx.root(), added, tx.project_lock()) {
        Ok(()) => error,
        Err(unroot) => io::Error::new(
            error.kind(),
            format!("{error}; taking the ledger back from the root record also failed: {unroot}"),
        ),
    }
}

/// A detached door's outputs, written back into its lock root.
fn write_back(lock_root: &Path, outputs: &Outputs) -> io::Result<()> {
    let root = ProjectRoot::open(lock_root)?;
    for file in outputs.files() {
        root.write_file_mode(
            &file.relative,
            &outputs.contents(file)?,
            file.mode as libc::mode_t,
        )?;
    }
    Ok(())
}

fn report(
    status: ExitStatus,
    outcome: ConfinedOutcome,
    ledger: Option<LedgerObjects>,
) -> DelegateReport {
    DelegateReport {
        status,
        stdout: outcome.stdout,
        stderr: outcome.stderr,
        ledger,
    }
}

/// The relay's report of the tool as an `ExitStatus`, the way a call site
/// reads any child's.
fn exit_status(status: ToolStatus) -> ExitStatus {
    match status {
        ToolStatus::Code(code) => ExitStatus::from_raw((code & 0xff) << 8),
        ToolStatus::Signal(signal) => ExitStatus::from_raw(signal & 0x7f),
    }
}

/// The session's private directory: 0700, under `$XDG_RUNTIME_DIR` (else
/// the temp dir), holding the proxy's socket. Removed when dropped.
struct SessionDir {
    dir: PathBuf,
    socket: PathBuf,
}

/// A Unix socket path must fit `sun_path` (108 bytes with its NUL).
const SUN_PATH_MAX: usize = 107;

impl SessionDir {
    fn create() -> io::Result<SessionDir> {
        let mut bases = Vec::new();
        if let Some(runtime) = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from) {
            if runtime.is_absolute() && runtime.is_dir() {
                bases.push(runtime);
            }
        }
        bases.push(std::env::temp_dir());
        bases.push(PathBuf::from("/tmp"));
        let name = format!(
            "tog-door-{}",
            hex::encode(crate::kernel::fsroot::urandom_bytes(8)?)
        );
        for base in bases {
            let dir = base.join(&name);
            let socket = dir.join("proxy.sock");
            if socket.as_os_str().len() > SUN_PATH_MAX {
                continue;
            }
            fs::DirBuilder::new().mode(0o700).create(&dir)?;
            return Ok(SessionDir { dir, socket });
        }
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "no directory for the proxy's socket has a path short enough for a Unix socket; \
             set XDG_RUNTIME_DIR or TMPDIR to a shorter one",
        ))
    }
}

impl Drop for SessionDir {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.socket);
        let _ = fs::remove_dir(&self.dir);
    }
}

/// The tog executable bound as the relay.
fn relay_executable() -> io::Result<PathBuf> {
    #[cfg(test)]
    if let Some(path) = RELAY_FOR_TEST.with(|relay| relay.borrow().clone()) {
        return Ok(path);
    }
    confine::running_executable()
}

fn socket_scan() -> SocketScan {
    #[cfg(all(test, debug_assertions))]
    if SKIP_SCAN_FOR_TEST.with(|skip| skip.get()) {
        return SocketScan::SkippedForTest;
    }
    SocketScan::Full
}

#[cfg(test)]
thread_local! {
    /// The tog binary a unit test binds as the relay (the test binary is
    /// not one).
    pub(crate) static RELAY_FOR_TEST: std::cell::RefCell<Option<PathBuf>> =
        const { std::cell::RefCell::new(None) };
    /// Skip the host socket scan, which the confine tests cover.
    pub(crate) static SKIP_SCAN_FOR_TEST: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::platform::Platform;
    use crate::kernel::policy::Attribution;
    use crate::kernel::resolve::confine::{Engine, Missing, TierOffer, TIERS_FOR_TEST};
    use crate::kernel::resolve::testing::Harness;
    use crate::kernel::testutil::TempDir;
    use std::collections::BTreeMap;

    /// `TOG_SANDBOX_TESTS=required` (any non-empty value) turns a skip into
    /// a panic, so CI cannot report a skipped check as passed.
    fn skip_or_panic(test: &str, reason: impl std::fmt::Display) {
        if matches!(std::env::var_os("TOG_SANDBOX_TESTS"), Some(value) if !value.is_empty()) {
            panic!("required Linux sandbox test {test} unavailable: {reason}");
        }
        eprintln!("skip {test}: {reason}");
    }

    /// The tog binary cargo built beside this test binary, which the
    /// sandbox binds as the relay; `None` (after a skip) when the host
    /// cannot run a confined door.
    fn relay(test: &str) -> Option<PathBuf> {
        if !matches!(Platform::host(), Ok(Platform::X86_64UnknownLinuxGnu)) {
            skip_or_panic(test, "not a supported Linux host");
            return None;
        }
        if let Err(error) = crate::kernel::sandbox::bwrap_preflight_with_activity(None) {
            skip_or_panic(test, format!("bubblewrap preflight failed: {error}"));
            return None;
        }
        let exe = std::env::current_exe().unwrap();
        let tog = exe
            .parent()
            .and_then(Path::parent)
            .map(|dir| dir.join("tog"));
        match tog {
            Some(tog) if tog.is_file() => Some(tog),
            _ => {
                skip_or_panic(
                    test,
                    format!(
                        "no tog binary beside {} (run `cargo test`, which builds it)",
                        exe.display()
                    ),
                );
                None
            }
        }
    }

    struct Fixture {
        harness: Harness,
        project: PathBuf,
        _temp: TempDir,
    }

    const PACKAGE_JSON: &[u8] = b"{\"dependencies\":{}}\n";
    const OLD_LOCK: &[u8] = b"old\n";

    fn fixture(label: &str) -> Fixture {
        let harness = Harness::new(label);
        let temp = TempDir::named(label);
        let project = temp.0.join("project");
        fs::create_dir_all(&project).unwrap();
        fs::write(project.join("package.json"), PACKAGE_JSON).unwrap();
        fs::write(project.join("deps.lock"), OLD_LOCK).unwrap();
        Fixture {
            harness,
            project: project.canonicalize().unwrap(),
            _temp: temp,
        }
    }

    /// Every file under `dir` with its bytes.
    fn tree(dir: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
        let mut files = BTreeMap::new();
        let mut pending = vec![dir.to_path_buf()];
        while let Some(next) = pending.pop() {
            for entry in fs::read_dir(&next).unwrap() {
                let path = entry.unwrap().path();
                let kind = fs::symlink_metadata(&path).unwrap().file_type();
                if kind.is_dir() {
                    pending.push(path);
                } else {
                    let relative = path.strip_prefix(dir).unwrap().to_path_buf();
                    files.insert(relative, fs::read(&path).unwrap_or_default());
                }
            }
        }
        files
    }

    /// A bash prelude: `get <route path>` prints the status line of one
    /// mirror request through the relay; `$BASE` is the route base and
    /// `$AUTH` the proxy credentials.
    const PRELUDE: &str = r#"set -u
path="${BASE#http://127.0.0.1:8119}"
send() {
    exec 3<>/dev/tcp/127.0.0.1/8119 || exit 90
    # "$(...)" dropped the request's final newline.
    printf '%s\n' "$1" >&3
    IFS= read -r line <&3
    cat <&3 >/dev/null
    exec 3<&-
    printf '%s\n' "${line%$'\r'}"
}
get() {
    send "$(printf 'GET %s%s HTTP/1.1\r\nHost: 127.0.0.1:8119\r\nConnection: close\r\n\r\n' "$path" "$1")"
}
"#;

    struct Outcome {
        result: io::Result<DelegateReport>,
        recorded: Vec<policy::Exception>,
    }

    /// Run `script` (after the prelude) through a confined door on the
    /// fixture project, with `deps.lock` and `new.lock` declared.
    fn run_door(
        fx: &Fixture,
        relay: Option<PathBuf>,
        script: &str,
        policy: Policy,
        adjust: impl FnOnce(&mut ConfinedSpec<'_>),
    ) -> Outcome {
        let _serial = policy::attribution_test_lock();
        RELAY_FOR_TEST.with(|slot| *slot.borrow_mut() = relay);
        SKIP_SCAN_FOR_TEST.with(|skip| skip.set(true));
        let mut attribution = Attribution::open("fixture").unwrap();
        let store = &fx.harness.store;
        let activity = &fx.harness.activity;
        let mut door = ResolutionDoor::open(
            store,
            activity,
            Platform::X86_64UnknownLinuxGnu,
            DoorKind::Edit,
            &mut attribution,
        )
        .unwrap();
        let mut spec = DelegateSpec::new("/usr/bin/bash");
        spec.args(["-c", &format!("{PRELUDE}{script}"), "tool"])
            .lock_root(&fx.project)
            .env("PATH", "/usr/bin:/bin")
            .capture();
        let mut confined = ConfinedSpec::new("fixture", "git", "runs a test script");
        confined.name = "the test tool";
        confined.outputs = vec![PathBuf::from("deps.lock"), PathBuf::from("new.lock")];
        confined.routes = vec![fx.harness.route()];
        confined.permitted = fx.harness.permitted();
        confined.proxy = Some(&fx.harness.proxy);
        confined.policy = Some(policy);
        confined.wire = Some(Box::new(|wire: &Wire<'_>| {
            let auth = crate::kernel::dirhash::base64_encode(
                format!("tog:{}", wire.address.token()).as_bytes(),
            );
            Ok(Wiring {
                args: with_forced(wire.args, wire.forced_args),
                env: vec![
                    ("BASE".into(), wire.address.route_base("fixture").into()),
                    ("AUTH".into(), auth.into()),
                ],
                ..Wiring::default()
            })
        }));
        adjust(&mut confined);
        let result = door.run_confined(spec, confined);
        let recorded = attribution.recorded();
        attribution.discard();
        Outcome { result, recorded }
    }

    fn deny(kinds: &[&str]) -> Policy {
        Policy {
            deny: kinds.iter().map(|kind| kind.to_string()).collect(),
            ..Policy::default()
        }
    }

    fn rooted(fx: &Fixture) -> BTreeSet<String> {
        let root = ProjectRoot::open(&fx.project).unwrap();
        let lock = fx.harness.store.project_lock_in(&root).unwrap();
        fx.harness
            .store
            .rooted_objects_locked(&fx.harness.activity, &root, &lock)
            .unwrap()
    }

    fn assert_untouched(fx: &Fixture, before: &BTreeMap<PathBuf, Vec<u8>>) {
        assert_eq!(&tree(&fx.project), before, "the project changed");
        assert!(rooted(fx).is_empty(), "{:?}", rooted(fx));
    }

    #[test]
    fn confined_door_publishes_a_fetched_output_and_roots_its_ledger() {
        let Some(relay) = relay("confined_door_publishes_a_fetched_output_and_roots_its_ledger")
        else {
            return;
        };
        let fx = fixture("door-e2e");
        let before = tree(&fx.project);
        let outcome = run_door(
            &fx,
            Some(relay),
            "get art/free-pkg-1.0.tgz > deps.lock\n",
            Policy::default(),
            |confined| {
                confined.target = Target::Project {
                    receipt: Some(Box::new(|facts: &PublishFacts<'_>| {
                        let lock = &facts.outputs[0];
                        let manifest = facts.input_digest(Path::new("package.json")).unwrap();
                        Ok(Some(
                            format!(
                                "{} {} {} {}\n",
                                facts.ledger.ledger,
                                hex::encode(lock.sha256),
                                hex::encode(manifest),
                                facts.isolation
                            )
                            .into_bytes(),
                        ))
                    })),
                };
            },
        );
        let report = outcome.result.unwrap();
        assert!(
            report.status.success(),
            "{}",
            String::from_utf8_lossy(&report.stderr)
        );
        let objects = report.ledger.unwrap();
        let lock = fs::read(fx.project.join("deps.lock")).unwrap();
        assert_eq!(lock, b"HTTP/1.1 200 OK\n");
        let receipt = fs::read_to_string(fx.project.join(".tog/resolution/fixture.json")).unwrap();
        use sha2::Digest as _;
        assert_eq!(
            receipt,
            format!(
                "{} {} {} confined\n",
                objects.ledger,
                hex::encode(sha2::Sha256::digest(&lock)),
                hex::encode(sha2::Sha256::digest(PACKAGE_JSON)),
            )
        );
        let store = &fx.harness.store;
        let portable =
            String::from_utf8(ledger::read_portable(store, &objects.ledger).unwrap()).unwrap();
        assert!(portable.contains("free-pkg-1.0.tgz"), "{portable}");
        let rooted = rooted(&fx);
        assert!(rooted.contains(&objects.ledger) && rooted.contains(&objects.diagnostics));
        assert_eq!(rooted.len(), 2, "the originals are released: {rooted:?}");
        let mut after = tree(&fx.project);
        after.remove(Path::new("deps.lock"));
        after.remove(Path::new(".tog/resolution/fixture.json"));
        let mut expected = before;
        expected.remove(Path::new("deps.lock"));
        assert_eq!(after, expected, "only the output and the receipt changed");
        assert!(outcome.recorded.is_empty(), "{:?}", outcome.recorded);
    }

    #[test]
    fn denied_kind_fails_the_door_even_when_the_tool_exits_zero() {
        let Some(relay) = relay("denied_kind_fails_the_door_even_when_the_tool_exits_zero") else {
            return;
        };
        let fx = fixture("door-denied");
        let before = tree(&fx.project);
        let outcome = run_door(
            &fx,
            Some(relay),
            "get meta/pkg.json > /dev/null; get art/weak-pkg-1.0.tgz > deps.lock; exit 0\n",
            deny(&[policy::WEAK_INTEGRITY]),
            |_| {},
        );
        let error = outcome.result.unwrap_err();
        assert!(error.to_string().contains("weak-integrity"), "{error}");
        assert!(outcome.recorded.is_empty(), "{:?}", outcome.recorded);
        assert_untouched(&fx, &before);
    }

    #[test]
    fn ledger_only_exceptions_are_recorded_on_the_owner_thread() {
        let Some(relay) = relay("ledger_only_exceptions_are_recorded_on_the_owner_thread") else {
            return;
        };
        let fx = fixture("door-recorded");
        let script = "get meta/pkg.json > /dev/null\n\
             get art/weak-pkg-1.0.tgz > deps.lock\n\
             send \"$(printf 'CONNECT github.com:9418 HTTP/1.1\\r\\nHost: github.com:9418\\r\\n\
             Proxy-Authorization: Basic %s\\r\\n\\r\\n' \"$AUTH\")\" >> deps.lock\n";
        let outcome = run_door(&fx, Some(relay), script, Policy::default(), |_| {});
        let report = outcome.result.unwrap();
        assert!(
            report.status.success(),
            "{}",
            String::from_utf8_lossy(&report.stderr)
        );
        let kinds: BTreeSet<&str> = outcome.recorded.iter().map(|e| e.kind.as_str()).collect();
        assert_eq!(
            kinds,
            BTreeSet::from([policy::WEAK_INTEGRITY, policy::GIT_DEPENDENCY]),
            "{:?}",
            outcome.recorded
        );
        let weak = outcome
            .recorded
            .iter()
            .find(|e| e.kind == policy::WEAK_INTEGRITY)
            .unwrap();
        assert_eq!(
            weak.subject,
            fx.harness.upstream_url("/art/weak-pkg-1.0.tgz")
        );
        assert_eq!(
            fs::read(fx.project.join("deps.lock")).unwrap(),
            b"HTTP/1.1 200 OK\nHTTP/1.1 403 Forbidden\n"
        );
    }

    #[test]
    fn output_containing_the_token_fails() {
        let Some(relay) = relay("output_containing_the_token_fails") else {
            return;
        };
        let fx = fixture("door-token");
        let before = tree(&fx.project);
        let outcome = run_door(
            &fx,
            Some(relay),
            "printf 'registry=%s\\n' \"$BASE\" > new.lock\n",
            Policy::default(),
            |_| {},
        );
        let error = outcome.result.unwrap_err();
        assert!(
            error.to_string().contains("the proxy session token"),
            "{error}"
        );
        assert!(error.to_string().contains("new.lock"), "{error}");
        assert_untouched(&fx, &before);
    }

    #[test]
    fn unconfined_resolution_is_refused_when_denied_and_recorded_otherwise() {
        let Some(relay) =
            relay("unconfined_resolution_is_refused_when_denied_and_recorded_otherwise")
        else {
            return;
        };
        let fx = fixture("door-unconfined");
        let before = tree(&fx.project);
        let unfenced = TierOffer {
            engine: Engine::Bubblewrap,
            fenced: false,
        };
        TIERS_FOR_TEST.with(|tiers| *tiers.borrow_mut() = Some((vec![unfenced], Vec::new())));
        let refused = run_door(
            &fx,
            Some(relay.clone()),
            "echo ran > deps.lock\n",
            deny(&[policy::UNCONFINED_RESOLUTION]),
            |_| {},
        );
        let error = refused.result.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported, "{error}");
        assert!(
            error.to_string().contains("unconfined-resolution"),
            "{error}"
        );
        assert_untouched(&fx, &before);

        // The run itself still uses bubblewrap: the override only changes
        // what the tier probe reports.
        let recorded = run_door(
            &fx,
            Some(relay),
            "echo ran > deps.lock\n",
            Policy::default(),
            |_| {},
        );
        TIERS_FOR_TEST.with(|tiers| *tiers.borrow_mut() = None);
        recorded.result.unwrap();
        assert_eq!(fs::read(fx.project.join("deps.lock")).unwrap(), b"ran\n");
        let kinds: Vec<&str> = recorded.recorded.iter().map(|e| e.kind.as_str()).collect();
        assert_eq!(kinds, [policy::UNCONFINED_RESOLUTION]);
        assert_eq!(recorded.recorded[0].subject, "the test tool");
    }

    #[test]
    fn no_tool_runs_unisolated_when_no_tier_is_available() {
        let fx = fixture("door-no-tier");
        let before = tree(&fx.project);
        let marker = fx._temp.0.join("ran");
        TIERS_FOR_TEST.with(|tiers| {
            *tiers.borrow_mut() = Some((
                Vec::new(),
                vec![Missing {
                    capability: "bubblewrap",
                    reason: "not installed".into(),
                    fix: "install bubblewrap".into(),
                }],
            ))
        });
        let outcome = run_door(
            &fx,
            None,
            &format!("touch {}\n", marker.display()),
            Policy::default(),
            |_| {},
        );
        TIERS_FOR_TEST.with(|tiers| *tiers.borrow_mut() = None);
        let error = outcome.result.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported, "{error}");
        let text = error.to_string();
        assert!(text.contains("the test tool runs a test script"), "{text}");
        assert!(
            text.contains("bubblewrap: not installed (fix: install bubblewrap)"),
            "{text}"
        );
        assert!(!marker.exists(), "the tool ran");
        assert_untouched(&fx, &before);
        let leftovers: Vec<_> = fs::read_dir(fx.harness.store.root.join("tmp"))
            .unwrap()
            .collect();
        assert!(
            leftovers.is_empty(),
            "nothing was snapshotted: {leftovers:?}"
        );
    }

    fn commit_failure_restores_every_output(label: &str, file: &'static str) {
        let Some(relay) = relay(label) else {
            return;
        };
        let fx = fixture(label);
        let before = tree(&fx.project);
        ledger::COMMIT_FAULT.with(|fault| fault.set(Some(file)));
        let outcome = run_door(
            &fx,
            Some(relay),
            "echo new > deps.lock; echo created > new.lock\n",
            Policy::default(),
            |_| {},
        );
        ledger::COMMIT_FAULT.with(|fault| fault.set(None));
        let error = outcome.result.unwrap_err();
        assert!(error.to_string().contains(file), "{error}");
        assert_untouched(&fx, &before);
    }

    #[test]
    fn ledger_commit_failure_restores_every_output() {
        commit_failure_restores_every_output(
            "ledger_commit_failure_restores_every_output",
            ledger::PORTABLE_FILE,
        );
    }

    #[test]
    fn sidecar_commit_failure_restores_every_output() {
        commit_failure_restores_every_output(
            "sidecar_commit_failure_restores_every_output",
            ledger::DIAGNOSTICS_FILE,
        );
    }

    #[test]
    fn descendant_writes_during_publication_do_not_reach_the_project() {
        let Some(relay) = relay("descendant_writes_during_publication_do_not_reach_the_project")
        else {
            return;
        };
        let fx = fixture("door-descendant");
        let script = "( sleep 1; echo late > deps.lock; echo late > package.json ) &\n\
             disown\n\
             echo good > deps.lock\n";
        let outcome = run_door(&fx, Some(relay), script, Policy::default(), |_| {});
        outcome.result.unwrap();
        std::thread::sleep(std::time::Duration::from_secs(2));
        assert_eq!(fs::read(fx.project.join("deps.lock")).unwrap(), b"good\n");
        assert_eq!(
            fs::read(fx.project.join("package.json")).unwrap(),
            PACKAGE_JSON
        );
        assert!(!fx.project.join("new.lock").exists());
    }

    #[test]
    fn forced_arguments_go_before_a_separator() {
        let args: Vec<OsString> = ["install", "--", "pkg"]
            .iter()
            .map(OsString::from)
            .collect();
        let forced: Vec<OsString> = ["--ignore-scripts"].iter().map(OsString::from).collect();
        assert_eq!(
            with_forced(&args, &forced),
            ["install", "--ignore-scripts", "--", "pkg"]
                .iter()
                .map(OsString::from)
                .collect::<Vec<_>>()
        );
    }
}

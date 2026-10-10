//! The resolution door: the one way tog starts a dependency tool that may
//! use the network or evaluate project code (`npm install
//! --package-lock-only`, `cargo generate-lockfile`, `bundle lock`, a Gemfile
//! check, and every other row of the census in the design).
//!
//! Every such child starts through [`ResolutionDoor::run_confined`]. Host-local
//! helpers start through `kernel::supervise`'s `local_*` functions instead,
//! which refuse a resolver program outside the reviewed offline forms
//! ([`tripwire`]), and clippy refuses the unrestricted supervise primitives
//! everywhere but the reviewed kernel sites. So a new resolver call site
//! cannot bypass the door by accident.
//!
//! The door has one mode: [`ResolutionDoor::run_confined`] runs the tool
//! isolated on a snapshot, through a proxy session, and publishes its
//! declared outputs all or nothing ([`door`]). A call site describes the
//! command as a [`DelegateSpec`] and the confinement as a
//! [`door::ConfinedSpec`]. There is no unsandboxed way through it: a host
//! that cannot isolate the tool refuses it, naming what is missing.
//!
//! The resolution proxy lives beside the door: the only network path of a
//! delegated dependency tool. It forwards only to permitted registries,
//! connects only to addresses it validated, verifies what registries
//! promise, and records every request in a ledger.

pub mod ca;
pub mod cache;
pub mod confine;
pub mod container;
pub mod door;
pub mod http;
pub mod iana;
pub(crate) mod inputs;
pub(crate) mod intercept;
pub mod keyscrub;
pub mod ledger;
pub mod mirror;
pub mod outputs;
pub mod proxy;
pub mod record;
pub mod redact;
pub mod relay;
pub mod routes;
pub mod seccomp;
pub mod session;
pub mod snapshot;
pub mod ssrf;
#[cfg(test)]
pub(crate) mod testing;
pub mod transaction;
pub(crate) mod tripwire;

use crate::kernel::activity::StoreActivity;
use crate::kernel::platform::Platform;
use crate::kernel::policy::Attribution;
use crate::kernel::resolve::ledger::LedgerObjects;
use crate::kernel::store::Store;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use std::rc::Rc;

/// Why a door runs a tool. Each census row has one; later the ledger
/// records it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DoorKind {
    /// `tog add` / `remove` / `update`: the tool edits the manifest and lock.
    Edit,
    /// A dependency lock the project (or an sdist) does not ship, generated
    /// by the ecosystem's own tool.
    MissingLock,
    /// A planning step that asks the tool (a consistency gate, a closure
    /// download, a lock parser) and writes no project input.
    Planner,
    /// `tog x`: resolving one registry tool into its `~/.tog/x` cache.
    X,
    /// `tog attest`: an ecosystem's lock-consistency check.
    Attest,
}

impl DoorKind {
    /// The name the ledger records.
    pub fn as_str(self) -> &'static str {
        match self {
            DoorKind::Edit => "edit",
            DoorKind::MissingLock => "missing-lock",
            DoorKind::Planner => "planner",
            DoorKind::X => "x",
            DoorKind::Attest => "attest",
        }
    }
}

/// The only way to run a dependency tool that may use the network or
/// evaluate project code. Borrowing the attribution ties every fact the
/// run produces to the scope that will publish (or discard) it.
pub struct ResolutionDoor<'a> {
    store: &'a Store,
    activity: &'a StoreActivity,
    platform: Platform,
    kind: DoorKind,
    attribution: &'a mut Attribution,
    /// Ledgers of Detached runs made with no project at hand (an sdist's
    /// Cargo.lock), shared with every reopened door, for whoever opened
    /// this one to root under its project ([`Self::take_kept_ledgers`]).
    kept: Rc<RefCell<Vec<LedgerObjects>>>,
}

impl<'a> ResolutionDoor<'a> {
    /// Open a door of `kind` on the scope `attribution` owns. The children
    /// it starts run under `activity`, the caller's lease on `store`.
    pub fn open(
        store: &'a Store,
        activity: &'a StoreActivity,
        platform: Platform,
        kind: DoorKind,
        attribution: &'a mut Attribution,
    ) -> io::Result<Self> {
        Ok(Self {
            store,
            activity,
            platform,
            kind,
            attribution,
            kept: Rc::default(),
        })
    }

    /// A door of another kind on the same scope, for a call that runs a
    /// second kind of tool inside the first (Python's missing requirements
    /// lock is generated while it plans). It borrows this door until it is
    /// dropped.
    pub fn reopen(&mut self, kind: DoorKind) -> ResolutionDoor<'_> {
        ResolutionDoor {
            store: self.store,
            activity: self.activity,
            platform: self.platform,
            kind,
            attribution: &mut *self.attribution,
            kept: Rc::clone(&self.kept),
        }
    }

    /// Keep the ledger of a Detached run that has no project to root it
    /// under, for the caller that opened this door.
    pub fn keep_ledger(&self, objects: LedgerObjects) {
        self.kept.borrow_mut().push(objects);
    }

    /// The ledgers kept so far (by this door or a reopened one), handed
    /// over once: the caller roots them under its project before its
    /// store lease ends, or GC may collect them.
    pub fn take_kept_ledgers(&self) -> Vec<LedgerObjects> {
        std::mem::take(&mut *self.kept.borrow_mut())
    }

    /// Run one tool invocation confined: isolated against a snapshot of
    /// its lock root, reaching the network only through a proxy session,
    /// its declared outputs published all or nothing (see [`door`]). A
    /// tool that exits nonzero is a report, not an error (each call site
    /// words its own failure), and nothing is published. A policy refusal, an offline miss, an
    /// undeclared write, a secret in an output, or a denied exception is
    /// an error, even when the tool exited 0.
    pub fn run_confined(
        &mut self,
        spec: DelegateSpec,
        confined: door::ConfinedSpec<'_>,
    ) -> io::Result<DelegateReport> {
        door::run(self, spec, confined)
    }

    /// The scope this door records into, lent back to the caller between
    /// runs (a tailor's `prepare` publishes nothing itself, but a registry
    /// tool's projection claims it).
    pub fn attribution(&mut self) -> &mut Attribution {
        self.attribution
    }

    pub fn store(&self) -> &'a Store {
        self.store
    }

    /// The caller's lease on the store, which every child this door starts
    /// runs under.
    pub fn lease(&self) -> &'a StoreActivity {
        self.activity
    }

    pub fn platform(&self) -> Platform {
        self.platform
    }
}

/// Where the tool's standard streams go.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DelegateStdio {
    /// Stdin, stdout and stderr are tog's own: the user watches the tool.
    #[default]
    Inherit,
    /// Stdin is empty and both outputs are captured into the report.
    Capture,
}

/// One tool invocation, described rather than built, so the door decides
/// how it runs. The builder methods mirror `std::process::Command`'s and
/// keep its environment semantics (a map of edits over the inherited
/// environment, or over nothing after `env_clear`), and the door applies
/// them to the tool it starts in isolation.
#[derive(Debug, Clone)]
pub struct DelegateSpec {
    /// The tool's executable, normally a store object path.
    pub program: PathBuf,
    pub args: Vec<OsString>,
    /// The directory the tool runs in: the project (or stage) whose lock it
    /// resolves. `None` runs it in tog's own working directory.
    pub lock_root: Option<PathBuf>,
    /// Variables set (`Some`) or removed (`None`) on top of the base
    /// environment, one final value per name.
    pub env: BTreeMap<OsString, Option<OsString>>,
    /// The base environment is empty rather than tog's own.
    pub env_clear: bool,
    pub stdio: DelegateStdio,
}

impl DelegateSpec {
    pub fn new(program: impl AsRef<OsStr>) -> Self {
        Self {
            program: PathBuf::from(program.as_ref()),
            args: Vec::new(),
            lock_root: None,
            env: BTreeMap::new(),
            env_clear: false,
            stdio: DelegateStdio::Inherit,
        }
    }

    pub fn arg(&mut self, arg: impl AsRef<OsStr>) -> &mut Self {
        self.args.push(arg.as_ref().to_os_string());
        self
    }

    pub fn args<I, S>(&mut self, args: I) -> &mut Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        for arg in args {
            self.arg(arg);
        }
        self
    }

    pub fn lock_root(&mut self, dir: impl AsRef<Path>) -> &mut Self {
        self.lock_root = Some(dir.as_ref().to_path_buf());
        self
    }

    pub fn env(&mut self, key: impl AsRef<OsStr>, value: impl AsRef<OsStr>) -> &mut Self {
        self.env.insert(
            key.as_ref().to_os_string(),
            Some(value.as_ref().to_os_string()),
        );
        self
    }

    pub fn env_remove(&mut self, key: impl AsRef<OsStr>) -> &mut Self {
        self.env.insert(key.as_ref().to_os_string(), None);
        self
    }

    /// Start from an empty environment. Like `Command::env_clear`, it also
    /// drops every edit made before it.
    pub fn env_clear(&mut self) -> &mut Self {
        self.env.clear();
        self.env_clear = true;
        self
    }

    /// `kernel::sandbox::force_env` for a spec: strip the inherited
    /// variables the tool must not see, then set tog's values last.
    pub fn force_env(
        &mut self,
        remove_prefixes: &[&str],
        remove: &[&str],
        set: &[(String, String)],
    ) -> &mut Self {
        for (key, value) in crate::kernel::sandbox::forced_env_edits(remove_prefixes, remove, set) {
            self.env.insert(key, value);
        }
        self
    }

    /// Capture stdout and stderr into the report instead of passing them
    /// through.
    pub fn capture(&mut self) -> &mut Self {
        self.stdio = DelegateStdio::Capture;
        self
    }

    /// Narrate the invocation under `-v`, the way `ui::trace_command` does
    /// for a `Command`.
    pub fn trace(&self) {
        crate::kernel::ui::trace_command(&self.command());
    }

    /// The command this spec describes, run as written. A host-local
    /// helper built with the same spec (a Go extraction with the proxy off)
    /// hands it to `kernel::supervise`'s `local_*` functions.
    pub fn command(&self) -> Command {
        let mut command = Command::new(&self.program);
        command.args(&self.args);
        if let Some(dir) = &self.lock_root {
            crate::kernel::fsroot::start_in(&mut command, dir);
        }
        if self.env_clear {
            command.env_clear();
        }
        for (key, value) in &self.env {
            match value {
                Some(value) => command.env(key, value),
                None => command.env_remove(key),
            };
        }
        command
    }
}

/// How one door run ended.
#[derive(Debug)]
pub struct DelegateReport {
    pub status: ExitStatus,
    /// Empty unless the spec captured its output.
    pub stdout: Vec<u8>,
    /// Empty unless the spec captured its output.
    pub stderr: Vec<u8>,
    /// The ledger and its sidecar a confined run committed. A project run
    /// rooted them in the project's record; a detached run's caller roots
    /// them itself before its store lease ends. `None` for a tool that
    /// failed.
    pub ledger: Option<ledger::LedgerObjects>,
}

/// For a caller that parses a captured run the way it parsed a
/// `std::process::Output`.
impl From<DelegateReport> for std::process::Output {
    fn from(report: DelegateReport) -> Self {
        Self {
            status: report.status,
            stdout: report.stdout,
            stderr: report.stderr,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envs(command: &Command) -> Vec<(OsString, Option<OsString>)> {
        command
            .get_envs()
            .map(|(key, value)| (key.to_os_string(), value.map(OsStr::to_os_string)))
            .collect()
    }

    /// The spec keeps `Command`'s own environment rules, so the command the
    /// door rebuilds is the one a call site used to build by hand: the last
    /// edit of a name wins, and `env_clear` drops the edits before it.
    #[test]
    fn a_spec_rebuilds_the_command_a_site_would_have_built() {
        let mut spec = DelegateSpec::new("/store/bin/tool");
        spec.args(["one", "two"])
            .arg("three")
            .lock_root("/project")
            .env("KEEP", "1")
            .env_remove("DROP")
            .env("DROP", "back")
            .env_remove("KEEP");
        let mut expected = Command::new("/store/bin/tool");
        expected
            .args(["one", "two", "three"])
            .current_dir("/project")
            .env("KEEP", "1")
            .env_remove("DROP")
            .env("DROP", "back")
            .env_remove("KEEP");
        let built = spec.command();
        assert_eq!(built.get_program(), expected.get_program());
        assert_eq!(
            built.get_args().collect::<Vec<_>>(),
            expected.get_args().collect::<Vec<_>>()
        );
        assert_eq!(built.get_current_dir(), expected.get_current_dir());
        assert_eq!(envs(&built), envs(&expected));

        let mut cleared = DelegateSpec::new("/store/bin/tool");
        cleared.env("GONE", "1").env_clear().env("PATH", "/usr/bin");
        let built = cleared.command();
        assert_eq!(
            envs(&built),
            [(OsString::from("PATH"), Some(OsString::from("/usr/bin")))]
        );
        assert!(DelegateSpec::new("x").command().get_current_dir().is_none());
    }
}

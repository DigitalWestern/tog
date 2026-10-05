//! Which host view a package's install scripts run in. On Linux they run
//! against the host's C runtime alone first, and against the whole host only
//! when that fails (`kernel::hostfallback`, #328); the env identity's
//! `build_view` input says so. A package whose scripts needed the whole host
//! records `host-build-inputs`, and the environment holding it is committed
//! under `hostfallback::fallback_identity`, never under the runtime-only id.

use super::realize::{classify_lifecycle_result, remove_dangling_bin_links, LifecycleFailure};
use super::*;
use crate::kernel::hostfallback::{
    self, Attempt, CachedObject, FallbackRecords, RUNTIME_ONLY_VIEW,
};
use crate::kernel::sandbox::{HostView, Sandbox};

/// Where a runtime-only env identity, realized on a host in a given state,
/// records the packages whose install scripts fell back to the whole host.
const RECORDS: FallbackRecords = FallbackRecords {
    kind: "node-env-host-fallback",
    names: |identity, name| identity.inputs.contains_key(&format!("pkg:{name}")),
    what: "npm install scripts",
};

/// What a `host-build-inputs` exception says about a package.
const HOST_BUILD_INPUTS_DETAIL: &str = "install scripts did not build against the C runtime \
     alone; rerun against this machine's development headers and libraries, so the package \
     depends on which -dev packages the host has";

/// The `build_view` a fresh env identity carries on `platform`: Linux runs
/// install scripts runtime-only first; macOS has no such view.
pub(super) fn build_view(platform: Platform) -> Option<&'static str> {
    (!platform.is_macos()).then_some(RUNTIME_ONLY_VIEW)
}

/// The env object already in the store for `identity`: the runtime-only
/// one, or the host-fallback one a recorded fallback on a host in this
/// state points at.
pub(super) fn cached_object(
    store: &Store,
    activity: &StoreActivity,
    identity: &Identity,
) -> io::Result<Option<CachedObject>> {
    RECORDS.cached_object(
        store,
        activity,
        identity,
        crate::kernel::hostview::host_build_inputs,
    )
}

/// The packages whose install scripts fell back to the whole host, and the
/// one host build inputs fingerprint they were all built against.
#[derive(Debug, Default)]
pub(super) struct ScriptsFallback {
    pub(super) fell_back: Vec<String>,
    pub(super) host_inputs: Option<String>,
}

impl ScriptsFallback {
    /// The identity the env is committed under: the runtime-only one when
    /// nothing fell back.
    pub(super) fn commit_identity(&self, identity: &Identity) -> Identity {
        match &self.host_inputs {
            Some(host_inputs) => {
                hostfallback::fallback_identity(identity, &self.fell_back, host_inputs)
            }
            None => identity.clone(),
        }
    }

    /// Record the fallback against the runtime-only identity, so the next
    /// sync on a host in this state finds the committed object.
    pub(super) fn record(&self, store: &Store, activity: &StoreActivity, identity: &Identity) {
        if let Some(host_inputs) = &self.host_inputs {
            RECORDS.record(store, activity, identity, host_inputs, &self.fell_back);
        }
    }
}

/// Refuse an exception the policy in force denies, recording nothing: the
/// check `hostfallback::hermetic_first` makes before it retries against the
/// whole host, so a denying policy stops the retry before it runs.
fn refuse_if_denied(kind: &str, subject: &str, detail: &str) -> io::Result<()> {
    let policy = crate::kernel::policy::effective();
    match crate::kernel::policy::denied(&policy, kind) {
        true => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            crate::kernel::policy::refusal(&policy, kind, subject, detail),
        )),
        false => Ok(()),
    }
}

/// One package's lifecycle work, ready to run: where it lives, the
/// snapshots a failed attempt is restored from, and the sandbox mounts and
/// environment every attempt gets.
pub(super) struct PackageScripts<'a> {
    pub(super) platform: Platform,
    pub(super) activity: &'a StoreActivity,
    pub(super) staged: &'a Path,
    pub(super) plan: &'a NpmPlan,
    pub(super) package: &'a NpmPackage,
    pub(super) pkg_dir: &'a Path,
    /// The package tree before any script ran, outside every mount.
    pub(super) snapshot: &'a Path,
    /// The scratch HOME, and its contents before any script ran (planted
    /// and provisioned artifacts), outside every mount.
    pub(super) tmp: &'a Path,
    pub(super) tmp_snapshot: &'a Path,
    pub(super) phases: &'a [(&'static str, String)],
    pub(super) envs: &'a [(String, String)],
    pub(super) path_env: &'a str,
    pub(super) read: Vec<&'a Path>,
}

impl PackageScripts<'_> {
    /// Run the package's phases in the view `identity` asks for, and fold a
    /// fallback into `fallback`. A script failure in every view restores the
    /// package from its snapshot and is recorded as an exception; strict
    /// policy turns the record into a hard error.
    pub(super) fn run(
        &self,
        identity: &Identity,
        fallback: &mut ScriptsFallback,
    ) -> io::Result<()> {
        let p = self.package;
        let build = |view: HostView| self.run_phases(view);
        let result =
            if identity.inputs.get("build_view").map(String::as_str) == Some(RUNTIME_ONLY_VIEW) {
                hostfallback::hermetic_first(
                    &p.path,
                    HOST_BUILD_INPUTS_DETAIL,
                    Attempt {
                        // Checked here, recorded below: a retry that fails
                        // too leaves the package as it was, built against
                        // nothing, and its exception is install-script-failed.
                        record: refuse_if_denied,
                        discard: || self.restore_attempt(),
                        fingerprint: crate::kernel::hostview::host_build_inputs,
                        build,
                    },
                )
            } else {
                build(HostView::Full).map(|()| None)
            };
        let e = match result {
            Ok(Some(host_inputs)) => {
                crate::kernel::policy::record(
                    crate::kernel::policy::HOST_BUILD_INPUTS,
                    &p.path,
                    HOST_BUILD_INPUTS_DETAIL,
                )?;
                hostfallback::same_host_state(&mut fallback.host_inputs, &p.path, host_inputs)?;
                fallback.fell_back.push(p.path.clone());
                return Ok(());
            }
            Ok(None) => return Ok(()),
            Err(e)
                if hostfallback::is_host_changed(&e)
                    || matches!(
                        e.kind(),
                        io::ErrorKind::Unsupported | io::ErrorKind::Interrupted
                    ) =>
            {
                return Err(e)
            }
            Err(e) => e,
        };
        let hint = "If this package downloads files at install time, declare them as verified inputs in package.json — \
                    \"tog\": {\"artifacts\": [{\"url\", \"sha256\", \"path\"}]} — \
                    placed where the package's downloader caches them (see README).";
        let error = e.to_string();
        let detail = format!("{}. {hint}", error.chars().take(300).collect::<String>());
        if let Err(policy_error) = crate::kernel::policy::record(
            crate::kernel::policy::INSTALL_SCRIPT_FAILED,
            &p.path,
            &detail,
        ) {
            return Err(err(format!(
                "{}: install script failed under the network-denied build \
                 sandbox: {e}. {hint} ({policy_error})",
                p.path
            )));
        }
        crate::kernel::store::remove_tree(self.pkg_dir)?;
        fs::rename(self.snapshot, self.pkg_dir)?;
        remove_dangling_bin_links(self.staged, self.plan)
    }

    /// Every phase in npm's order under `view`, stopping at the first
    /// failure. A failure names its phase. A missing sandbox backend or an
    /// interrupt keeps its kind, so it never becomes a script failure.
    fn run_phases(&self, view: HostView) -> io::Result<()> {
        let p = self.package;
        let sandbox = Sandbox {
            read: self.read.clone(),
            write: vec![self.pkg_dir, self.tmp],
            host_view: view,
        };
        let mode = match view {
            HostView::Full => "sandboxed",
            HostView::RuntimeOnly => "sandboxed, C runtime only",
        };
        for (phase, script) in self.phases {
            crate::kernel::ui::note(&format!("{} {}: {phase} ({mode})", p.name, p.version));
            let envs_phase: Vec<(String, String)> = self
                .envs
                .iter()
                .cloned()
                .chain([("npm_lifecycle_event".to_string(), phase.to_string())])
                .collect();
            let result = sandbox.run_in_on(
                self.platform,
                &["/bin/sh", "-c", script],
                self.path_env,
                self.tmp,
                self.pkg_dir,
                &envs_phase,
                Some(self.activity),
            );
            match classify_lifecycle_result(result) {
                Ok(()) => {}
                Err(LifecycleFailure::SandboxUnavailable(e)) => return Err(e),
                Err(LifecycleFailure::Interrupted(e)) => {
                    return Err(io::Error::new(
                        e.kind(),
                        format!("{}: {phase}: {e}; the sync stopped here", p.path),
                    ))
                }
                Err(LifecycleFailure::Script(e)) => {
                    return Err(io::Error::new(e.kind(), format!("{phase}: {e}")))
                }
            }
        }
        Ok(())
    }

    /// Undo a failed attempt before the retry: the package tree and the
    /// scratch HOME go back to their snapshots, which stay in place for a
    /// failure of the retry.
    fn restore_attempt(&self) -> io::Result<()> {
        for (live, snapshot) in [(self.pkg_dir, self.snapshot), (self.tmp, self.tmp_snapshot)] {
            crate::kernel::store::remove_tree(live)?;
            crate::comforter::clone_tree_with_activity(
                self.activity,
                snapshot,
                live,
                self.platform,
            )?;
        }
        remove_dangling_bin_links(self.staged, self.plan)
    }
}

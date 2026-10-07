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
    refuse_with(&crate::kernel::policy::effective(), kind, subject, detail)
}

/// `refuse_if_denied` under `policy`.
fn refuse_with(
    policy: &crate::kernel::policy::Policy,
    kind: &str,
    subject: &str,
    detail: &str,
) -> io::Result<()> {
    match crate::kernel::policy::denied(policy, kind) {
        true => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            crate::kernel::policy::refusal(policy, kind, subject, detail),
        )),
        false => Ok(()),
    }
}

/// How one package's scripts ended.
#[derive(Debug)]
enum ScriptsOutcome {
    /// They ran; when they fell back, the host build inputs fingerprint
    /// they were built against.
    Built(Option<String>),
    /// The sync stops here: the policy refused the fallback, the host
    /// changed under the retry, the sandbox could not be set up, or tog was
    /// asked to stop.
    Stop(io::Error),
    /// The scripts failed in every view they were allowed to run in: an
    /// `install-script-failed` exception.
    Failed(io::Error),
}

/// Run `build` in the view `identity` asks for: against the C runtime
/// alone first when its `build_view` is runtime-only, retrying against the
/// whole host when `refuse` allows `host-build-inputs`; against the whole
/// host once otherwise. A refusal stops the sync, as it does for gems and
/// sdists (`hostfallback::hermetic_first`): it is told apart from a script
/// that fails with the same error kind by whether `refuse` refused.
fn scripts_in_view(
    identity: &Identity,
    subject: &str,
    refuse: impl FnOnce(&str, &str, &str) -> io::Result<()>,
    discard: impl FnOnce() -> io::Result<()>,
    fingerprint: impl FnMut() -> io::Result<String>,
    mut build: impl FnMut(HostView) -> io::Result<()>,
) -> ScriptsOutcome {
    let refused = std::cell::Cell::new(false);
    let result = if identity.inputs.get("build_view").map(String::as_str) == Some(RUNTIME_ONLY_VIEW)
    {
        hostfallback::hermetic_first(
            subject,
            HOST_BUILD_INPUTS_DETAIL,
            Attempt {
                record: |kind: &str, subject: &str, detail: &str| {
                    let checked = refuse(kind, subject, detail);
                    refused.set(checked.is_err());
                    checked
                },
                discard,
                fingerprint,
                build,
            },
        )
    } else {
        build(HostView::Full).map(|()| None)
    };
    match result {
        Ok(host_inputs) => ScriptsOutcome::Built(host_inputs),
        Err(e)
            if refused.get()
                || hostfallback::is_host_changed(&e)
                || matches!(
                    e.kind(),
                    io::ErrorKind::Unsupported | io::ErrorKind::Interrupted
                ) =>
        {
            ScriptsOutcome::Stop(e)
        }
        Err(e) => ScriptsOutcome::Failed(e),
    }
}

/// What an `install-script-failed` exception and its strict-policy error
/// tell the user to try.
const ARTIFACTS_HINT: &str =
    "If this package downloads files at install time, declare them as verified inputs in package.json — \
     \"tog\": {\"artifacts\": [{\"url\", \"sha256\", \"path\"}]} — \
     placed where the package's downloader caches them (see README).";

/// How much of a script failure's message the exception detail keeps.
const DETAIL_CHARS: usize = 300;

/// The `install-script-failed` detail for `error`: its first
/// `DETAIL_CHARS` characters and `ARTIFACTS_HINT`. A script that failed in
/// both views carries the whole-host retry's error first
/// (`hostfallback::hermetic_first`), so the cut keeps the error left to
/// fix and drops the hermetic attempt's, not the other way round.
fn script_failure_detail(error: &io::Error) -> String {
    let error = error.to_string();
    format!(
        "{}. {ARTIFACTS_HINT}",
        error.chars().take(DETAIL_CHARS).collect::<String>()
    )
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
    /// policy turns the record into a hard error. A policy that denies
    /// `host-build-inputs` stops the sync before the retry runs.
    pub(super) fn run(
        &self,
        identity: &Identity,
        fallback: &mut ScriptsFallback,
    ) -> io::Result<()> {
        let p = self.package;
        let e = match scripts_in_view(
            identity,
            &p.path,
            // Checked here, recorded below: a retry that fails too leaves
            // the package as it was, built against nothing, and its
            // exception is install-script-failed.
            refuse_if_denied,
            || self.restore_attempt(),
            crate::kernel::hostview::host_build_inputs,
            |view| self.run_phases(view),
        ) {
            ScriptsOutcome::Built(Some(host_inputs)) => {
                crate::kernel::policy::record(
                    crate::kernel::policy::HOST_BUILD_INPUTS,
                    &p.path,
                    HOST_BUILD_INPUTS_DETAIL,
                )?;
                hostfallback::same_host_state(&mut fallback.host_inputs, &p.path, host_inputs)?;
                fallback.fell_back.push(p.path.clone());
                return Ok(());
            }
            ScriptsOutcome::Built(None) => return Ok(()),
            ScriptsOutcome::Stop(e) => return Err(e),
            ScriptsOutcome::Failed(e) => e,
        };
        let detail = script_failure_detail(&e);
        if let Err(policy_error) = crate::kernel::policy::record(
            crate::kernel::policy::INSTALL_SCRIPT_FAILED,
            &p.path,
            &detail,
        ) {
            return Err(err(format!(
                "{}: install script failed under the network-denied build \
                 sandbox: {e}. {ARTIFACTS_HINT} ({policy_error})",
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

#[cfg(test)]
mod tests {
    use super::*;

    const HOST: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const SUBJECT: &str = "node_modules/fixture-pkg";

    fn identity(view: Option<&str>) -> Identity {
        Identity {
            kind: "node-env".into(),
            name: "env".into(),
            version: "1".into(),
            inputs: view
                .map(|view| ("build_view".to_string(), view.to_string()))
                .into_iter()
                .collect(),
        }
    }

    fn deny_host_build_inputs() -> crate::kernel::policy::Policy {
        crate::kernel::policy::Policy {
            deny: [crate::kernel::policy::HOST_BUILD_INPUTS.to_string()]
                .into_iter()
                .collect(),
            ..crate::kernel::policy::Policy::default()
        }
    }

    /// `scripts_in_view` under `policy` with scripted attempt results,
    /// returning the outcome and the views tried in order.
    fn scripted(
        identity: &Identity,
        policy: &crate::kernel::policy::Policy,
        mut results: Vec<io::Result<()>>,
    ) -> (ScriptsOutcome, Vec<HostView>) {
        results.reverse();
        let mut views = Vec::new();
        let outcome = scripts_in_view(
            identity,
            SUBJECT,
            |kind, subject, detail| refuse_with(policy, kind, subject, detail),
            || Ok(()),
            || Ok(HOST.to_string()),
            |view| {
                views.push(view);
                results.pop().expect("an attempt the test did not script")
            },
        );
        (outcome, views)
    }

    fn failed(kind: io::ErrorKind, what: &str) -> io::Result<()> {
        Err(io::Error::new(kind, format!("postinstall: {what}")))
    }

    /// A policy that denies `host-build-inputs` stops the sync before the
    /// retry runs, as it does for gems and sdists: the package is not
    /// rolled back into an `install-script-failed` exception.
    #[test]
    fn a_denied_fallback_stops_the_sync_without_running_against_the_host() {
        let (outcome, views) = scripted(
            &identity(Some(RUNTIME_ONLY_VIEW)),
            &deny_host_build_inputs(),
            vec![failed(io::ErrorKind::Other, "zlib.h not found")],
        );
        let ScriptsOutcome::Stop(error) = outcome else {
            panic!("a denied fallback did not stop the sync: {outcome:?}");
        };
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        let message = error.to_string();
        assert!(message.contains("zlib.h not found"), "{message}");
        assert!(
            message.contains("policy denies host-build-inputs"),
            "{message}"
        );
        assert_eq!(views, [HostView::RuntimeOnly]);
    }

    /// A script that fails in both views is an ordinary script failure,
    /// even when its own error has the kind a refusal carries.
    #[test]
    fn a_script_failing_in_every_view_is_a_script_failure() {
        let (outcome, views) = scripted(
            &identity(Some(RUNTIME_ONLY_VIEW)),
            &crate::kernel::policy::Policy::default(),
            vec![
                failed(io::ErrorKind::Other, "zlib.h not found"),
                failed(io::ErrorKind::PermissionDenied, "EACCES"),
            ],
        );
        assert!(
            matches!(&outcome, ScriptsOutcome::Failed(error) if error.kind() == io::ErrorKind::PermissionDenied),
            "{outcome:?}"
        );
        assert_eq!(views, [HostView::RuntimeOnly, HostView::Full]);
    }

    /// The exception detail of a script that failed in both views is cut at
    /// `DETAIL_CHARS`, and what it keeps is the whole-host retry's error:
    /// a hermetic error longer than the cut, which led before #609, no
    /// longer hides it.
    #[test]
    fn the_detail_of_a_script_failing_in_every_view_keeps_the_retrys_error() {
        let hermetic = format!("zlib.h: No such file or directory {}", "-".repeat(400));
        let retry = "node-gyp: could not find node headers for v24";
        let (outcome, _) = scripted(
            &identity(Some(RUNTIME_ONLY_VIEW)),
            &crate::kernel::policy::Policy::default(),
            vec![
                failed(io::ErrorKind::Other, &hermetic),
                failed(io::ErrorKind::Other, retry),
            ],
        );
        let ScriptsOutcome::Failed(error) = outcome else {
            panic!("a script failing in every view is not a script failure: {outcome:?}");
        };
        let detail = script_failure_detail(&error);
        let kept = detail.strip_suffix(&format!(". {ARTIFACTS_HINT}")).unwrap();
        assert_eq!(kept.chars().count(), DETAIL_CHARS, "{detail}");
        assert!(
            kept.starts_with("the build against this machine's whole /usr failed (postinstall: "),
            "{detail}"
        );
        assert!(kept.contains(retry), "{detail}");
        assert!(!kept.contains(&hermetic), "{detail}");
        assert!(error.to_string().contains(&hermetic), "{error}");
    }

    #[test]
    fn an_allowed_fallback_builds_against_the_host() {
        let (outcome, views) = scripted(
            &identity(Some(RUNTIME_ONLY_VIEW)),
            &crate::kernel::policy::Policy::default(),
            vec![failed(io::ErrorKind::Other, "zlib.h not found"), Ok(())],
        );
        assert!(
            matches!(&outcome, ScriptsOutcome::Built(Some(host)) if host == HOST),
            "{outcome:?}"
        );
        assert_eq!(views, [HostView::RuntimeOnly, HostView::Full]);
    }

    /// Without a runtime-only view (macOS) the scripts run once against the
    /// whole host, and a denying policy never comes into it.
    #[test]
    fn scripts_without_a_runtime_only_view_run_once_against_the_host() {
        let (outcome, views) = scripted(
            &identity(None),
            &deny_host_build_inputs(),
            vec![failed(io::ErrorKind::PermissionDenied, "EACCES")],
        );
        assert!(matches!(outcome, ScriptsOutcome::Failed(_)), "{outcome:?}");
        assert_eq!(views, [HostView::Full]);
    }
}

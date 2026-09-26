//! How a gem with native extensions is built on Linux: against the host's
//! C runtime alone first, and against the whole host only when that fails
//! (issue #304). A fallback is a `host-build-inputs` exception, and the
//! object it produces is committed under its own identity, so it never
//! answers for the runtime-only one.

use super::*;

pub(super) const RUNTIME_ONLY_VIEW: &str = "runtime-only/1";
const HOST_FALLBACK_VIEW: &str = "host-fallback/1";

/// The store record kind naming, for a runtime-only gems identity built
/// on a host in a given state, the gems that fell back to the whole host.
const HOST_FALLBACK_RECORDS: &str = "ruby-gems-host-fallback";

/// This host's `hostview::host_build_inputs`, walked at most once per
/// sync and only when a runtime-only gems object is missing: a cache hit
/// never pays for it.
pub(super) fn host_inputs(slot: &mut Option<String>) -> io::Result<String> {
    if let Some(fingerprint) = slot {
        return Ok(fingerprint.clone());
    }
    let fingerprint = crate::kernel::hostview::host_build_inputs()
        .map_err(|e| io::Error::new(e.kind(), format!("fingerprint the host build inputs: {e}")))?;
    *slot = Some(fingerprint.clone());
    Ok(fingerprint)
}

/// The identity a gems object is committed under when `fell_back` gems
/// were rebuilt against the whole host: the runtime-only identity, with
/// the view renamed, the fallen-back gems listed, and the fingerprint of
/// the host state they were built against (`host_inputs`). Two hosts, or
/// one host before and after a development package changed, get
/// different ids; the object never answers for the runtime-only identity.
pub(super) fn ruby_gems_fallback_identity(
    runtime_only: &Identity,
    fell_back: &[String],
    host_inputs: &str,
) -> Identity {
    let mut identity = runtime_only.clone();
    identity
        .inputs
        .insert("build_view".to_string(), HOST_FALLBACK_VIEW.to_string());
    identity
        .inputs
        .insert("host_fallback".to_string(), sorted(fell_back).join(","));
    identity
        .inputs
        .insert("host_inputs".to_string(), host_inputs.to_string());
    identity
}

fn sorted(names: &[String]) -> Vec<String> {
    let mut names = names.to_vec();
    names.sort();
    names.dedup();
    names
}

/// A fallback record's key: the runtime-only id and the host fingerprint,
/// so a host in another state finds no record and builds.
fn record_key(runtime_only: &Identity, host_inputs: &str) -> String {
    serde_json::json!([runtime_only.object_id(), host_inputs]).to_string()
}

/// The gems a previous build of `runtime_only`, on a host whose build
/// inputs had this fingerprint, rebuilt against the whole host, as its
/// store record says. A record that names a gem outside the plan, or no
/// gem, is ignored.
fn recorded_host_fallback(
    store: &Store,
    runtime_only: &Identity,
    host_inputs: &str,
) -> io::Result<Option<Vec<String>>> {
    let key = record_key(runtime_only, host_inputs);
    let Some(value) = store.read_record(HOST_FALLBACK_RECORDS, &key)? else {
        return Ok(None);
    };
    let names: Option<Vec<String>> = value["host_fallback"].as_array().and_then(|names| {
        names
            .iter()
            .map(|name| name.as_str().map(str::to_string))
            .collect()
    });
    Ok(names.filter(|names| {
        !names.is_empty()
            && names
                .iter()
                .all(|name| runtime_only.inputs.contains_key(&format!("gem:{name}")))
    }))
}

/// The gems object already in the store for `identity`: the runtime-only
/// object itself, or, when a build of it on a host in this host's state
/// fell back, the host-fallback object that build committed. Rebuilding
/// would only fall back again against the same host inputs, so the record
/// stands in for the attempt. The fingerprint is taken only past the
/// first check, into `host_inputs_slot`.
pub(super) fn cached_gems_object(
    store: &Store,
    activity: &StoreActivity,
    identity: &Identity,
    host_inputs_slot: &mut Option<String>,
) -> io::Result<Option<String>> {
    let id = identity.object_id();
    if store.has_with_activity(activity, &id)? {
        return Ok(Some(id));
    }
    if identity.inputs.get("build_view").map(String::as_str) != Some(RUNTIME_ONLY_VIEW) {
        return Ok(None);
    }
    let host_inputs = host_inputs(host_inputs_slot)?;
    let Some(fell_back) = recorded_host_fallback(store, identity, &host_inputs)? else {
        return Ok(None);
    };
    let fallback = ruby_gems_fallback_identity(identity, &fell_back, &host_inputs).object_id();
    Ok(store
        .has_with_activity(activity, &fallback)?
        .then_some(fallback))
}

/// Record which gems of `runtime_only` fell back against these host
/// inputs, so the next sync over the same store on a host in the same
/// state finds the host-fallback object instead of building again. A
/// failed write costs that sync a rebuild and nothing else, so it is
/// reported and the sync goes on.
pub(super) fn record_host_fallback(
    store: &Store,
    activity: &StoreActivity,
    runtime_only: &Identity,
    host_inputs: &str,
    fell_back: &[String],
) {
    let value = serde_json::json!({ "host_fallback": sorted(fell_back) });
    let key = record_key(runtime_only, host_inputs);
    if let Err(error) = store.write_record(activity, HOST_FALLBACK_RECORDS, &key, &value) {
        ui::note(&format!(
            "gems built against the whole host were not recorded in the store ({error}); \
             the next sync builds them again"
        ));
    }
}

/// Where the gems of one plan install from and into: the Ruby object, the
/// install helper, the scratch directory holding the helper and each
/// `.gem`, and the staged GEM_HOME every gem shares.
pub(super) struct GemInstall<'a> {
    pub(super) platform: Platform,
    pub(super) activity: &'a StoreActivity,
    pub(super) ruby_obj: &'a Path,
    pub(super) helper: &'a Path,
    pub(super) scratch: &'a Path,
    pub(super) staged: &'a Path,
}

impl GemInstall<'_> {
    /// Install `gem` from its `.gem` at `named` in the sandbox, with the
    /// host view its build needs (`install_gem`); `true` when it fell back
    /// to the whole host. Each attempt gets its own empty HOME and TMPDIR
    /// (`AttemptHomes`); the helper and the `.gem` stay readable from the
    /// outer scratch.
    pub(super) fn install(&self, gem: &RubyGem, named: &Path, native: bool) -> io::Result<bool> {
        let (platform, ruby_obj, scratch, staged) =
            (self.platform, self.ruby_obj, self.scratch, self.staged);
        let mut homes = AttemptHomes::new(scratch, &gem.full_name);
        let install = |host_view: HostView| {
            let home = homes.next()?;
            let spec = BuildSpec {
                argv: vec![
                    ruby_obj.join("bin/ruby").display().to_string(),
                    self.helper.display().to_string(),
                    "install".to_string(),
                    named.display().to_string(),
                    staged.display().to_string(),
                ],
                cwd: home.clone(),
                env: vec![
                    ("GEM_HOME".to_string(), staged.display().to_string()),
                    ("GEM_PATH".to_string(), staged.display().to_string()),
                    ("BUNDLE_IGNORE_CONFIG".to_string(), "1".to_string()),
                ],
                read: vec![ruby_obj.to_path_buf(), scratch.to_path_buf()],
                write: vec![staged.to_path_buf()],
                scratch: home,
                path: format!("{}:/usr/bin:/bin", ruby_obj.join("bin").display()),
                host_view,
            };
            crate::kernel::sandbox::run_build_spec_on_with_activity(platform, &spec, self.activity)
        };
        // What the GEM_HOME held before a hermetic attempt, so a failed one
        // can be undone before the retry (see `gem_home`).
        let hermetic = native && !platform.is_macos();
        let before = hermetic.then(|| gem_home::manifest(staged)).transpose()?;
        let discard = || match &before {
            Some(before) => gem_home::discard_failed_attempt(staged, &gem.full_name, before),
            None => Ok(()),
        };
        let attempt = Attempt {
            record: crate::kernel::policy::record,
            discard,
            install,
        };
        install_gem(platform, native, &gem.full_name, attempt).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!(
                    "{}: sandboxed gem install failed: {e}\n(network is denied inside the \
                     sandbox, so a gem whose installer downloads anything cannot be installed)",
                    gem.full_name
                ),
            )
        })
    }
}

/// The HOME and TMPDIR of each attempt at one gem's install: a fresh empty
/// directory under the scratch directory. Every attempt can read the whole
/// scratch directory (the helper and the `.gem` live there), so the
/// previous attempt's directory is removed before the next one is made:
/// nothing a failed attempt left behind reaches the retry.
struct AttemptHomes<'a> {
    scratch: &'a Path,
    gem: &'a str,
    count: u32,
    current: Option<PathBuf>,
}

impl<'a> AttemptHomes<'a> {
    fn new(scratch: &'a Path, gem: &'a str) -> Self {
        Self {
            scratch,
            gem,
            count: 0,
            current: None,
        }
    }

    fn next(&mut self) -> io::Result<PathBuf> {
        if let Some(previous) = self.current.take() {
            crate::kernel::store::remove_tree(&previous).map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!(
                        "remove the failed attempt's home {}: {e}",
                        previous.display()
                    ),
                )
            })?;
        }
        self.count += 1;
        let home = self
            .scratch
            .join(format!("{}-attempt-{}", self.gem, self.count));
        fs::create_dir(&home)?;
        self.current = Some(home.clone());
        Ok(home)
    }
}

/// One gem's install as `install_gem` drives it: `record` records an
/// exception, `discard` undoes what a failed hermetic attempt left in the
/// GEM_HOME (or refuses), and `install` runs one attempt with a view.
struct Attempt<R, D, I> {
    record: R,
    discard: D,
    install: I,
}

/// Install one gem with the host view its build needs, and say whether it
/// fell back to the whole host. A gem whose gemspec declares native
/// extensions builds hermetic-first on Linux (`install_hermetic_first`). A
/// pure-Ruby gem compiles nothing, so no view can change its bytes: it
/// installs once against `HostView::Full`, skips the view's setup cost,
/// and never records `host-build-inputs`. On macOS Seatbelt has no
/// C-runtime-only view yet (see `HostView`), so a second attempt would
/// only repeat the first.
fn install_gem<R, D, I>(
    platform: Platform,
    native: bool,
    gem: &str,
    mut attempt: Attempt<R, D, I>,
) -> io::Result<bool>
where
    R: FnOnce(&str, &str, &str) -> io::Result<()>,
    D: FnOnce() -> io::Result<()>,
    I: FnMut(HostView) -> io::Result<()>,
{
    if native && !platform.is_macos() {
        install_hermetic_first(gem, attempt)
    } else {
        (attempt.install)(HostView::Full).map(|()| false)
    }
}

/// What a `host-build-inputs` exception says about a gem.
const HOST_BUILD_INPUTS_DETAIL: &str = "native extension did not build against the C runtime \
     alone; rebuilt against this machine's development headers and libraries, so the object \
     depends on which -dev packages the host has";

/// Install one gem against the host's C runtime alone, and only if that
/// build fails, against the whole host; `true` when it fell back. The
/// fallback is an exception, and it is recorded before the second attempt
/// runs, so a policy that denies `host-build-inputs` stops here with
/// nothing built against the host.
///
/// A sandbox that could not be set up, or a run tog was asked to stop,
/// says nothing about the gem and is returned as is.
///
/// Before the retry, `discard` removes what the failed attempt left in the
/// shared GEM_HOME and refuses when the attempt changed anything beyond
/// RubyGems' own leftovers for this gem (`gem_home::discard_failed_attempt`);
/// a refusal records nothing.
fn install_hermetic_first<R, D, I>(gem: &str, mut attempt: Attempt<R, D, I>) -> io::Result<bool>
where
    R: FnOnce(&str, &str, &str) -> io::Result<()>,
    D: FnOnce() -> io::Result<()>,
    I: FnMut(HostView) -> io::Result<()>,
{
    let hermetic = match (attempt.install)(HostView::RuntimeOnly) {
        Ok(()) => return Ok(false),
        Err(error) => error,
    };
    if matches!(
        hermetic.kind(),
        io::ErrorKind::Unsupported | io::ErrorKind::Interrupted
    ) {
        return Err(hermetic);
    }
    let attempts = format!("the build against the C runtime alone failed ({hermetic})");
    let refused = (attempt.discard)().and_then(|()| {
        (attempt.record)(
            crate::kernel::policy::HOST_BUILD_INPUTS,
            gem,
            HOST_BUILD_INPUTS_DETAIL,
        )
    });
    if let Err(refusal) = refused {
        return Err(io::Error::new(
            refusal.kind(),
            format!("{attempts}, and it was not retried against the whole host: {refusal}"),
        ));
    }
    (attempt.install)(HostView::Full)
        .map(|()| true)
        .map_err(|full| {
            io::Error::new(
                full.kind(),
                format!(
                    "{attempts}, and so did the build against this machine's whole /usr ({full})"
                ),
            )
        })
}

#[cfg(test)]
mod tests {
    use super::super::tests::linux_test_plan;
    use super::*;
    use crate::kernel::testutil::TempDir;

    /// Runs `install_hermetic_first` with scripted attempt results and a
    /// real attribution frame, returning the result, the views tried in
    /// order, and what was recorded.
    fn hermetic_first(
        policy: &crate::kernel::policy::Policy,
        results: Vec<io::Result<()>>,
    ) -> (
        io::Result<bool>,
        Vec<HostView>,
        Vec<crate::kernel::policy::Exception>,
    ) {
        hermetic_first_discarding(policy, results, Ok(()))
    }

    /// `hermetic_first` with `discard` scripted too.
    fn hermetic_first_discarding(
        policy: &crate::kernel::policy::Policy,
        mut results: Vec<io::Result<()>>,
        discard: io::Result<()>,
    ) -> (
        io::Result<bool>,
        Vec<HostView>,
        Vec<crate::kernel::policy::Exception>,
    ) {
        let _lock = crate::kernel::policy::attribution_test_lock();
        let attribution = crate::kernel::policy::Attribution::open("ruby").unwrap();
        let mut views = Vec::new();
        results.reverse();
        let result = install_hermetic_first(
            "nokogiri-1.18.10",
            Attempt {
                record: |kind: &str, subject: &str, detail: &str| {
                    crate::kernel::policy::record_with(policy, kind, subject, detail)
                },
                discard: || discard,
                install: |view| {
                    views.push(view);
                    results.pop().expect("an attempt the test did not script")
                },
            },
        );
        let recorded = attribution.recorded();
        attribution.discard();
        (result, views, recorded)
    }

    fn failed(what: &str) -> io::Result<()> {
        Err(io::Error::other(format!(
            "sandboxed command failed: {what}"
        )))
    }

    #[test]
    fn a_gem_that_builds_against_the_c_runtime_records_nothing() {
        let (result, views, recorded) =
            hermetic_first(&crate::kernel::policy::Policy::default(), vec![Ok(())]);
        assert!(!result.unwrap());
        assert_eq!(views, [HostView::RuntimeOnly]);
        assert!(recorded.is_empty(), "{recorded:?}");
    }

    #[test]
    fn a_gem_that_needs_the_host_is_rebuilt_and_recorded() {
        let (result, views, recorded) = hermetic_first(
            &crate::kernel::policy::Policy::default(),
            vec![failed("lzma.h not found"), Ok(())],
        );
        assert!(result.unwrap(), "the gem fell back");
        assert_eq!(views, [HostView::RuntimeOnly, HostView::Full]);
        assert_eq!(recorded.len(), 1, "{recorded:?}");
        assert_eq!(recorded[0].kind, crate::kernel::policy::HOST_BUILD_INPUTS);
        assert_eq!(recorded[0].subject, "nokogiri-1.18.10");
        assert_eq!(recorded[0].detail, HOST_BUILD_INPUTS_DETAIL);
    }

    /// A policy that denies the kind stops before anything is built
    /// against the host, and says the hermetic build is what failed.
    #[test]
    fn a_denied_fallback_never_builds_against_the_host() {
        let policy = crate::kernel::policy::Policy {
            deny: [crate::kernel::policy::HOST_BUILD_INPUTS.to_string()]
                .into_iter()
                .collect(),
            ..crate::kernel::policy::Policy::default()
        };
        let (result, views, recorded) = hermetic_first(&policy, vec![failed("lzma.h not found")]);
        let error = result.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        let message = error.to_string();
        assert!(message.contains("C runtime alone failed"), "{message}");
        assert!(message.contains("lzma.h not found"), "{message}");
        assert!(
            message.contains("policy denies host-build-inputs"),
            "{message}"
        );
        assert_eq!(views, [HostView::RuntimeOnly]);
        assert!(recorded.is_empty(), "{recorded:?}");
    }

    /// A gems object built with a fallback has its own id, which names the
    /// gems that fell back, and never the runtime-only id.
    #[test]
    fn a_fallback_object_is_keyed_by_the_gems_that_fell_back() {
        let mut plan = linux_test_plan();
        let mut second = plan.gems[0].clone();
        second.name = "nokogiri".into();
        second.version = "1.18.10".into();
        second.full_name = "nokogiri-1.18.10".into();
        plan.gems.push(second);
        let runtime_only = ruby_gems_identity(&pin_spec(Platform::X86_64UnknownLinuxGnu), &plan);
        let host = "a".repeat(64);
        let one = ruby_gems_fallback_identity(&runtime_only, &["nokogiri-1.18.10".into()], &host);
        let both = ruby_gems_fallback_identity(
            &runtime_only,
            &["rake-13.2.1".into(), "nokogiri-1.18.10".into()],
            &host,
        );
        // The same gems against another host state.
        let upgraded = ruby_gems_fallback_identity(
            &runtime_only,
            &["nokogiri-1.18.10".into()],
            &"b".repeat(64),
        );
        assert_eq!(one.inputs["build_view"], HOST_FALLBACK_VIEW);
        assert_eq!(one.inputs["host_fallback"], "nokogiri-1.18.10");
        assert_eq!(one.inputs["host_inputs"], host);
        assert_eq!(both.inputs["host_fallback"], "nokogiri-1.18.10,rake-13.2.1");
        let ids = [
            runtime_only.object_id(),
            one.object_id(),
            both.object_id(),
            upgraded.object_id(),
        ];
        for (index, id) in ids.iter().enumerate() {
            assert!(!ids[index + 1..].contains(id), "{ids:?}");
        }
        // Order of discovery does not matter.
        let reordered = ruby_gems_fallback_identity(
            &runtime_only,
            &["nokogiri-1.18.10".into(), "rake-13.2.1".into()],
            &host,
        );
        assert_eq!(reordered.object_id(), both.object_id());
        crate::tailors::install_kinds();
        for identity in [&one, &both, &upgraded] {
            crate::kernel::objmeta::check_identity_grammar(identity).unwrap();
        }
        let mut unfingerprinted = one.clone();
        unfingerprinted.inputs.remove("host_inputs");
        assert!(crate::kernel::objmeta::check_identity_grammar(&unfingerprinted).is_err());
    }

    /// The runtime-only object answers first; without it, the record of
    /// this machine's last fallback leads to the host-fallback object, and
    /// only when that object is still there.
    #[test]
    fn a_recorded_fallback_leads_to_the_fallback_object() {
        use std::os::unix::fs::PermissionsExt;
        let temp = TempDir::named("ruby-host-fallback");
        let root = temp.0.join("store");
        for sub in ["objects", "meta", "tmp"] {
            fs::create_dir_all(root.join(sub)).unwrap();
        }
        let store = Store {
            root: root.canonicalize().unwrap(),
        };
        let activity = store
            .activity(crate::kernel::activity::ActivityMode::Shared)
            .unwrap();
        let plant = |id: &str| {
            let object = store.object_path(id);
            fs::create_dir(&object).unwrap();
            fs::set_permissions(&object, fs::Permissions::from_mode(0o555)).unwrap();
            fs::write(store.root.join("meta").join(format!("{id}.json")), "{}").unwrap();
        };
        let runtime_only = ruby_gems_identity(
            &pin_spec(Platform::X86_64UnknownLinuxGnu),
            &linux_test_plan(),
        );
        let (host, upgraded) = ("a".repeat(64), "b".repeat(64));
        let fallback = ruby_gems_fallback_identity(&runtime_only, &["rake-13.2.1".into()], &host);
        let lookup = |host: &str| {
            let mut slot = Some(host.to_string());
            cached_gems_object(&store, &activity, &runtime_only, &mut slot).unwrap()
        };
        let fell_back = ["rake-13.2.1".to_string()];

        plant(&fallback.object_id());
        assert_eq!(lookup(&host), None, "no record, no fallback object");
        record_host_fallback(&store, &activity, &runtime_only, &host, &fell_back);
        assert_eq!(lookup(&host), Some(fallback.object_id()));
        // A host whose build inputs changed finds no record, and builds.
        assert_eq!(lookup(&upgraded), None);

        // A record naming a gem outside the plan is ignored.
        store
            .write_record(
                &activity,
                HOST_FALLBACK_RECORDS,
                &record_key(&runtime_only, &host),
                &serde_json::json!({"host_fallback": ["rails-8.0.0"]}),
            )
            .unwrap();
        assert_eq!(lookup(&host), None);
        record_host_fallback(&store, &activity, &runtime_only, &host, &fell_back);

        // The runtime-only object wins over any record.
        plant(&runtime_only.object_id());
        assert_eq!(lookup(&upgraded), Some(runtime_only.object_id()));
        // And a hit on it never fingerprints the host.
        let mut slot = None;
        assert_eq!(
            cached_gems_object(&store, &activity, &runtime_only, &mut slot).unwrap(),
            Some(runtime_only.object_id())
        );
        assert_eq!(slot, None);
        for id in [runtime_only.object_id(), fallback.object_id()] {
            fs::set_permissions(store.object_path(&id), fs::Permissions::from_mode(0o755)).unwrap();
        }
    }

    /// The retry against the whole host starts in a fresh home, and the
    /// failed attempt's home is gone before it starts: nothing the first
    /// attempt left in its HOME or TMPDIR is readable to the second.
    #[test]
    fn the_retry_never_sees_the_failed_attempts_home() {
        let scratch = TempDir::named("ruby-attempt-homes");
        let mut homes = AttemptHomes::new(&scratch.0, "nokogiri-1.18.10");
        let mut seen = Vec::new();
        let result = install_hermetic_first(
            "nokogiri-1.18.10",
            Attempt {
                record: |_: &str, _: &str, _: &str| Ok(()),
                discard: || Ok(()),
                install: |view| {
                    let home = homes.next()?;
                    assert_eq!(fs::read_dir(&home)?.count(), 0, "a home that is not empty");
                    seen.push(home.clone());
                    match view {
                        HostView::RuntimeOnly => {
                            fs::create_dir(home.join("tmp"))?;
                            fs::write(home.join("tmp/probe-result"), "yes")?;
                            failed("lzma.h not found")
                        }
                        HostView::Full => {
                            assert!(
                                !seen[0].exists(),
                                "the failed attempt's home is still there"
                            );
                            Ok(())
                        }
                    }
                },
            },
        );
        assert!(result.unwrap(), "the gem fell back");
        assert_eq!(seen.len(), 2);
        assert_ne!(seen[0], seen[1]);
        assert!(!seen[0].exists() && seen[1].is_dir());
    }

    /// A failed attempt that changed the GEM_HOME beyond its own leftovers
    /// is not retried, and nothing is recorded.
    #[test]
    fn a_failed_attempt_that_touched_other_gems_is_not_retried() {
        let (result, views, recorded) = hermetic_first_discarding(
            &crate::kernel::policy::Policy::default(),
            vec![failed("lzma.h not found")],
            Err(io::Error::other("the failed build changed bin/rake")),
        );
        let message = result.unwrap_err().to_string();
        assert!(message.contains("lzma.h not found"), "{message}");
        assert!(message.contains("not retried"), "{message}");
        assert!(message.contains("bin/rake"), "{message}");
        assert_eq!(views, [HostView::RuntimeOnly]);
        assert!(recorded.is_empty(), "{recorded:?}");
    }

    #[test]
    fn a_gem_that_fails_both_ways_names_both_attempts() {
        let (result, views, _) = hermetic_first(
            &crate::kernel::policy::Policy::default(),
            vec![failed("first"), failed("second")],
        );
        let message = result.unwrap_err().to_string();
        assert!(message.contains("C runtime alone failed"), "{message}");
        assert!(message.contains("first"), "{message}");
        assert!(message.contains("whole /usr"), "{message}");
        assert!(message.contains("second"), "{message}");
        assert_eq!(views, [HostView::RuntimeOnly, HostView::Full]);
    }

    /// Only a gem with native extensions pays for the C-runtime-only view
    /// and can fall back; a pure-Ruby gem installs once against the full
    /// view even when that install fails, and records nothing.
    #[test]
    fn only_native_gems_build_hermetic_first() {
        let _lock = crate::kernel::policy::attribution_test_lock();
        let attribution = crate::kernel::policy::Attribution::open("ruby").unwrap();
        fn attempt(
            views: &mut Vec<HostView>,
            full: io::Result<()>,
        ) -> Attempt<
            fn(&str, &str, &str) -> io::Result<()>,
            fn() -> io::Result<()>,
            impl FnMut(HostView) -> io::Result<()> + '_,
        > {
            let mut full = Some(full);
            Attempt {
                record: |kind, subject, detail| {
                    crate::kernel::policy::record_with(
                        &crate::kernel::policy::Policy::default(),
                        kind,
                        subject,
                        detail,
                    )
                },
                discard: || Ok(()),
                install: move |view| {
                    views.push(view);
                    match view {
                        HostView::RuntimeOnly => failed("lzma.h not found"),
                        HostView::Full => full.take().expect("one full attempt"),
                    }
                },
            }
        }
        let linux = Platform::X86_64UnknownLinuxGnu;
        let mut native_views = Vec::new();
        let used_host = install_gem(
            linux,
            true,
            "nokogiri-1.18.10",
            attempt(&mut native_views, Ok(())),
        )
        .unwrap();
        assert!(used_host);
        assert_eq!(native_views, [HostView::RuntimeOnly, HostView::Full]);
        assert_eq!(attribution.recorded().len(), 1);

        crate::kernel::policy::clear();
        let mut pure_views = Vec::new();
        let result = install_gem(
            linux,
            false,
            "rake-13.4.2",
            attempt(&mut pure_views, failed("rake")),
        );
        assert!(result.is_err());
        assert_eq!(pure_views, [HostView::Full]);
        assert!(attribution.recorded().is_empty());

        let mut darwin_views = Vec::new();
        let used_host = install_gem(
            Platform::Aarch64AppleDarwin,
            true,
            "nokogiri-1.18.10",
            attempt(&mut darwin_views, Ok(())),
        )
        .unwrap();
        assert!(!used_host, "the only attempt is no fallback");
        assert_eq!(darwin_views, [HostView::Full]);
        attribution.discard();
    }

    /// A sandbox that could not start, or a stop request, is not the gem
    /// failing to build: no exception, no second attempt.
    #[test]
    fn setup_failures_and_interrupts_are_not_retried() {
        for kind in [io::ErrorKind::Unsupported, io::ErrorKind::Interrupted] {
            let (result, views, recorded) = hermetic_first(
                &crate::kernel::policy::Policy::default(),
                vec![Err(io::Error::new(kind, "bwrap: setup"))],
            );
            assert_eq!(result.unwrap_err().kind(), kind);
            assert_eq!(views, [HostView::RuntimeOnly]);
            assert!(recorded.is_empty(), "{recorded:?}");
        }
    }
}

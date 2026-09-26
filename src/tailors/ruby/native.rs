//! How a gem with native extensions is built on Linux: against the host's
//! C runtime alone first, and against the whole host only when that fails
//! (issue #304). A fallback is a `host-build-inputs` exception, and the
//! object it produces is committed under its own identity, so it never
//! answers for the runtime-only one.

use super::*;

pub(super) const RUNTIME_ONLY_VIEW: &str = "runtime-only/1";
const HOST_FALLBACK_VIEW: &str = "host-fallback/1";

/// The store record kind naming, for a runtime-only gems identity, the
/// gems that fell back to the whole host when it was last built here.
const HOST_FALLBACK_RECORDS: &str = "ruby-gems-host-fallback";

/// The identity a gems object is committed under when `fell_back` gems
/// were rebuilt against the whole host: the runtime-only identity, with
/// the view renamed and the fallen-back gems listed. Its bytes still
/// depend on the host's development packages; the id only keeps such an
/// object from ever answering for the runtime-only identity.
pub(super) fn ruby_gems_fallback_identity(
    runtime_only: &Identity,
    fell_back: &[String],
) -> Identity {
    let mut names = fell_back.to_vec();
    names.sort();
    names.dedup();
    let mut identity = runtime_only.clone();
    identity
        .inputs
        .insert("build_view".to_string(), HOST_FALLBACK_VIEW.to_string());
    identity
        .inputs
        .insert("host_fallback".to_string(), names.join(","));
    identity
}

/// The gems a previous build of `runtime_only` on this machine rebuilt
/// against the whole host, as its store record says. A record that names a
/// gem outside the plan, or no gem, is ignored.
fn recorded_host_fallback(
    store: &Store,
    runtime_only: &Identity,
) -> io::Result<Option<Vec<String>>> {
    let Some(value) = store.read_record(HOST_FALLBACK_RECORDS, &runtime_only.object_id())? else {
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
/// object itself, or, when this machine's last build of it fell back, the
/// host-fallback object that build committed. Rebuilding would only fall
/// back again on the same host, so the record stands in for the attempt.
pub(super) fn cached_gems_object(
    store: &Store,
    activity: &StoreActivity,
    identity: &Identity,
) -> io::Result<Option<String>> {
    let id = identity.object_id();
    if store.has_with_activity(activity, &id)? {
        return Ok(Some(id));
    }
    if identity.inputs.get("build_view").map(String::as_str) != Some(RUNTIME_ONLY_VIEW) {
        return Ok(None);
    }
    let Some(fell_back) = recorded_host_fallback(store, identity)? else {
        return Ok(None);
    };
    let fallback = ruby_gems_fallback_identity(identity, &fell_back).object_id();
    Ok(store
        .has_with_activity(activity, &fallback)?
        .then_some(fallback))
}

/// Record which gems of `runtime_only` fell back, so the next sync on this
/// machine finds the host-fallback object instead of building again. A
/// failed write costs the next sync a rebuild and nothing else, so it is
/// reported and the sync goes on.
pub(super) fn record_host_fallback(
    store: &Store,
    activity: &StoreActivity,
    runtime_only: &Identity,
    fell_back: &[String],
) {
    let mut names = fell_back.to_vec();
    names.sort();
    names.dedup();
    let value = serde_json::json!({ "host_fallback": names });
    if let Err(error) = store.write_record(
        activity,
        HOST_FALLBACK_RECORDS,
        &runtime_only.object_id(),
        &value,
    ) {
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
    /// to the whole host. Each attempt gets its own empty HOME and TMPDIR,
    /// so nothing a failed attempt left there reaches the next one; the
    /// helper and the `.gem` stay readable from the outer scratch.
    pub(super) fn install(&self, gem: &RubyGem, named: &Path, native: bool) -> io::Result<bool> {
        let (platform, ruby_obj, scratch, staged) =
            (self.platform, self.ruby_obj, self.scratch, self.staged);
        let mut attempts = 0;
        let install = |host_view: HostView| {
            attempts += 1;
            let home = scratch.join(format!("{}-attempt-{attempts}", gem.full_name));
            fs::create_dir(&home)?;
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
        let one = ruby_gems_fallback_identity(&runtime_only, &["nokogiri-1.18.10".into()]);
        let both = ruby_gems_fallback_identity(
            &runtime_only,
            &["rake-13.2.1".into(), "nokogiri-1.18.10".into()],
        );
        assert_eq!(one.inputs["build_view"], HOST_FALLBACK_VIEW);
        assert_eq!(one.inputs["host_fallback"], "nokogiri-1.18.10");
        assert_eq!(both.inputs["host_fallback"], "nokogiri-1.18.10,rake-13.2.1");
        let ids = [runtime_only.object_id(), one.object_id(), both.object_id()];
        assert!(
            ids[0] != ids[1] && ids[1] != ids[2] && ids[0] != ids[2],
            "{ids:?}"
        );
        // Order of discovery does not matter.
        let reordered = ruby_gems_fallback_identity(
            &runtime_only,
            &["nokogiri-1.18.10".into(), "rake-13.2.1".into()],
        );
        assert_eq!(reordered.object_id(), both.object_id());
        crate::tailors::install_kinds();
        for identity in [&one, &both] {
            crate::kernel::objmeta::check_identity_grammar(identity).unwrap();
        }
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
        let fallback = ruby_gems_fallback_identity(&runtime_only, &["rake-13.2.1".into()]);
        let lookup = || cached_gems_object(&store, &activity, &runtime_only).unwrap();

        plant(&fallback.object_id());
        assert_eq!(lookup(), None, "no record, no fallback object");
        record_host_fallback(&store, &activity, &runtime_only, &["rake-13.2.1".into()]);
        assert_eq!(lookup(), Some(fallback.object_id()));

        // A record naming a gem outside the plan is ignored.
        store
            .write_record(
                &activity,
                HOST_FALLBACK_RECORDS,
                &runtime_only.object_id(),
                &serde_json::json!({"host_fallback": ["rails-8.0.0"]}),
            )
            .unwrap();
        assert_eq!(lookup(), None);
        record_host_fallback(&store, &activity, &runtime_only, &["rake-13.2.1".into()]);

        // The runtime-only object wins over any record.
        plant(&runtime_only.object_id());
        assert_eq!(lookup(), Some(runtime_only.object_id()));
        for id in [runtime_only.object_id(), fallback.object_id()] {
            fs::set_permissions(store.object_path(&id), fs::Permissions::from_mode(0o755)).unwrap();
        }
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

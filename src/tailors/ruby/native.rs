//! How a gem with native extensions is built on Linux: against the host's
//! C runtime alone first, and against the whole host only when that fails
//! (issue #304). A fallback is a `host-build-inputs` exception, and the
//! object it produces is committed under its own identity, so it never
//! answers for the runtime-only one.

use super::*;

use crate::kernel::hostfallback::{self, FallbackRecords};

pub(super) use crate::kernel::hostfallback::{same_host_state, RUNTIME_ONLY_VIEW};

/// Where a runtime-only gems identity, built on a host in a given state,
/// records the gems that fell back to the whole host.
const HOST_FALLBACK_RECORDS: FallbackRecords = FallbackRecords {
    kind: "ruby-gems-host-fallback",
    names: |identity, name| identity.inputs.contains_key(&format!("gem:{name}")),
    what: "gems",
};

/// The identity a gems object is committed under when `fell_back` gems
/// were rebuilt against the whole host (`hostfallback::fallback_identity`).
pub(super) fn ruby_gems_fallback_identity(
    runtime_only: &Identity,
    fell_back: &[String],
    host_inputs: &str,
) -> Identity {
    hostfallback::fallback_identity(runtime_only, fell_back, host_inputs)
}

/// The gems object already in the store for `identity`, the runtime-only
/// one or the host-fallback one a recorded fallback points at
/// (`FallbackRecords::cached_object`).
pub(super) fn cached_gems_object(
    store: &Store,
    activity: &StoreActivity,
    identity: &Identity,
    fingerprint: impl FnOnce() -> io::Result<String>,
) -> io::Result<Option<String>> {
    Ok(HOST_FALLBACK_RECORDS
        .cached_object(store, activity, identity, fingerprint)?
        .map(|cached| cached.id))
}

/// Record which gems of `runtime_only` fell back against these host inputs
/// (`FallbackRecords::record`).
pub(super) fn record_host_fallback(
    store: &Store,
    activity: &StoreActivity,
    runtime_only: &Identity,
    host_inputs: &str,
    fell_back: &[String],
) {
    HOST_FALLBACK_RECORDS.record(store, activity, runtime_only, host_inputs, fell_back);
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
    /// tog's native library set, which native gems build with
    /// (`native_libs`).
    pub(super) native_libs: Option<&'a Path>,
}

impl GemInstall<'_> {
    /// Install `gem` from its `.gem` at `named` in the sandbox, with the
    /// host view its build needs (`install_gem`); when it fell back to the
    /// whole host, the host build inputs fingerprint it was built against.
    /// Each attempt gets its own empty HOME and TMPDIR
    /// (`AttemptHomes`); the helper and the `.gem` stay readable from the
    /// outer scratch.
    pub(super) fn install(
        &self,
        gem: &RubyGem,
        named: &Path,
        native: bool,
    ) -> io::Result<Option<String>> {
        let (platform, ruby_obj, scratch, staged) =
            (self.platform, self.ruby_obj, self.scratch, self.staged);
        let mut homes = AttemptHomes::new(scratch, &gem.full_name);
        // Only a native gem compiles anything, so only its build gets the
        // native library set.
        let native_libs = self.native_libs.filter(|_| native);
        let install = |host_view: HostView| {
            let home = homes.next()?;
            let mut argv = vec![
                ruby_obj.join("bin/ruby").display().to_string(),
                self.helper.display().to_string(),
                "install".to_string(),
                named.display().to_string(),
                staged.display().to_string(),
            ];
            let mut env = vec![
                ("GEM_HOME".to_string(), staged.display().to_string()),
                ("GEM_PATH".to_string(), staged.display().to_string()),
                ("BUNDLE_IGNORE_CONFIG".to_string(), "1".to_string()),
            ];
            let mut read = vec![ruby_obj.to_path_buf(), scratch.to_path_buf()];
            if let Some(set) = native_libs {
                argv.push(set.display().to_string());
                env.extend(super::native_libs::build_env(set, host_view));
                read.push(set.to_path_buf());
            }
            // The test stand-in for host development packages is part of
            // the whole host, so only the whole-host attempt sees it.
            if host_view == HostView::Full {
                if let Some(dev) = crate::kernel::hostview::test_host_dev_files() {
                    super::native_libs::add_host_dev_files(&mut env, &dev);
                    read.push(dev);
                }
            }
            let spec = BuildSpec {
                argv,
                cwd: home.clone(),
                env,
                read,
                write: vec![staged.to_path_buf()],
                scratch: home,
                // The set's own tools (`xml2-config`, `curl-config`) follow
                // the store Ruby.
                path: match native_libs {
                    Some(set) => format!(
                        "{}:{}:/usr/bin:/bin",
                        ruby_obj.join("bin").display(),
                        set.join("bin").display()
                    ),
                    None => format!("{}:/usr/bin:/bin", ruby_obj.join("bin").display()),
                },
                host_view,
            };
            crate::kernel::sandbox::run_build_spec_on(platform, &spec, Some(self.activity))
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
            fingerprint: crate::kernel::hostview::host_build_inputs,
            build: install,
        };
        install_gem(platform, native, &gem.full_name, attempt).map_err(|e| {
            if hostfallback::is_host_changed(&e) {
                return e;
            }
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

use crate::kernel::hostfallback::Attempt;

/// Install one gem with the host view its build needs, and say whether it
/// fell back to the whole host. A gem whose gemspec declares native
/// extensions builds hermetic-first on Linux (`install_hermetic_first`). A
/// pure-Ruby gem compiles nothing, so no view can change its bytes: it
/// installs once against `HostView::Full`, skips the view's setup cost,
/// and never records `host-build-inputs`. On macOS Seatbelt has no
/// C-runtime-only view yet (see `HostView`), so a second attempt would
/// only repeat the first.
fn install_gem<R, D, F, I>(
    platform: Platform,
    native: bool,
    gem: &str,
    mut attempt: Attempt<R, D, F, I>,
) -> io::Result<Option<String>>
where
    R: FnOnce(&str, &str, &str) -> io::Result<()>,
    D: FnOnce() -> io::Result<()>,
    F: FnMut() -> io::Result<String>,
    I: FnMut(HostView) -> io::Result<()>,
{
    if native && !platform.is_macos() {
        install_hermetic_first(gem, attempt)
    } else {
        (attempt.build)(HostView::Full).map(|()| None)
    }
}

/// What a `host-build-inputs` exception says about a gem.
const HOST_BUILD_INPUTS_DETAIL: &str = "native extension did not build against the C runtime \
     alone; rebuilt against this machine's development headers and libraries, so the object \
     depends on which -dev packages the host has";

/// Install one gem against the host's C runtime alone, and only if that
/// build fails, against the whole host (`hostfallback::hermetic_first`).
/// Before the retry, `discard` removes what the failed attempt left in the
/// shared GEM_HOME and refuses when the attempt changed anything beyond
/// RubyGems' own leftovers for this gem (`gem_home::discard_failed_attempt`).
fn install_hermetic_first<R, D, F, I>(
    gem: &str,
    attempt: Attempt<R, D, F, I>,
) -> io::Result<Option<String>>
where
    R: FnOnce(&str, &str, &str) -> io::Result<()>,
    D: FnOnce() -> io::Result<()>,
    F: FnMut() -> io::Result<String>,
    I: FnMut(HostView) -> io::Result<()>,
{
    hostfallback::hermetic_first(gem, HOST_BUILD_INPUTS_DETAIL, attempt)
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
        io::Result<Option<String>>,
        Vec<HostView>,
        Vec<crate::kernel::policy::Exception>,
    ) {
        hermetic_first_scripted(policy, results, Ok(()), vec![HOST.into(); 2])
    }

    /// The host build inputs fingerprint the scripted host keeps.
    const HOST: &str = "1111111111111111111111111111111111111111111111111111111111111111";

    /// `hermetic_first` with `discard` scripted too.
    fn hermetic_first_discarding(
        policy: &crate::kernel::policy::Policy,
        results: Vec<io::Result<()>>,
        discard: io::Result<()>,
    ) -> (
        io::Result<Option<String>>,
        Vec<HostView>,
        Vec<crate::kernel::policy::Exception>,
    ) {
        hermetic_first_scripted(policy, results, discard, vec![HOST.into(); 2])
    }

    /// `hermetic_first` with `discard` and the host fingerprints, in the
    /// order they are taken, scripted too.
    fn hermetic_first_scripted(
        policy: &crate::kernel::policy::Policy,
        mut results: Vec<io::Result<()>>,
        discard: io::Result<()>,
        mut fingerprints: Vec<String>,
    ) -> (
        io::Result<Option<String>>,
        Vec<HostView>,
        Vec<crate::kernel::policy::Exception>,
    ) {
        fingerprints.reverse();
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
                fingerprint: || {
                    Ok(fingerprints
                        .pop()
                        .expect("a fingerprint the test did not script"))
                },
                build: |view| {
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
        assert_eq!(result.unwrap(), None);
        assert_eq!(views, [HostView::RuntimeOnly]);
        assert!(recorded.is_empty(), "{recorded:?}");
    }

    #[test]
    fn a_gem_that_needs_the_host_is_rebuilt_and_recorded() {
        let (result, views, recorded) = hermetic_first(
            &crate::kernel::policy::Policy::default(),
            vec![failed("lzma.h not found"), Ok(())],
        );
        assert_eq!(result.unwrap().as_deref(), Some(HOST), "the gem fell back");
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
        let runtime_only =
            ruby_gems_identity(&pin_spec(Platform::X86_64UnknownLinuxGnu), &plan, None);
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
        assert_eq!(one.inputs["build_view"], hostfallback::HOST_FALLBACK_VIEW);
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
        let store = Store::for_test(root.canonicalize().unwrap());
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
            None,
        );
        let (host, upgraded) = ("a".repeat(64), "b".repeat(64));
        let fallback = ruby_gems_fallback_identity(&runtime_only, &["rake-13.2.1".into()], &host);
        let lookup = |host: &str| {
            cached_gems_object(&store, &activity, &runtime_only, || Ok(host.to_string())).unwrap()
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
                HOST_FALLBACK_RECORDS.kind,
                &FallbackRecords::key(&runtime_only, &host),
                &serde_json::json!({"host_fallback": ["rails-8.0.0"]}),
            )
            .unwrap();
        assert_eq!(lookup(&host), None);
        record_host_fallback(&store, &activity, &runtime_only, &host, &fell_back);

        // The runtime-only object wins over any record.
        plant(&runtime_only.object_id());
        assert_eq!(lookup(&upgraded), Some(runtime_only.object_id()));
        // And a hit on it never fingerprints the host.
        assert_eq!(
            cached_gems_object(&store, &activity, &runtime_only, || {
                panic!("a runtime-only hit fingerprinted the host")
            })
            .unwrap(),
            Some(runtime_only.object_id())
        );
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
                fingerprint: || Ok(HOST.to_string()),
                build: |view| {
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
        assert_eq!(result.unwrap().as_deref(), Some(HOST), "the gem fell back");
        assert_eq!(seen.len(), 2);
        assert_ne!(seen[0], seen[1]);
        assert!(!seen[0].exists() && seen[1].is_dir());
    }

    /// A host whose build inputs change while the build against it runs
    /// fails the gem: its object could not be keyed by one host state.
    #[test]
    fn a_host_that_changes_under_the_fallback_fails_it() {
        let upgraded = "2".repeat(64);
        let (result, views, _) = hermetic_first_scripted(
            &crate::kernel::policy::Policy::default(),
            vec![failed("lzma.h not found"), Ok(())],
            Ok(()),
            vec![HOST.into(), upgraded],
        );
        let error = result.unwrap_err();
        assert!(error
            .get_ref()
            .is_some_and(|inner| inner.is::<hostfallback::HostChanged>()));
        assert_eq!(
            error.to_string(),
            "host development files changed during the build of nokogiri-1.18.10; re-run tog"
        );
        assert_eq!(views, [HostView::RuntimeOnly, HostView::Full]);

        // Two fallbacks of one object against different host states fail
        // the same way; the same state twice is one state.
        let mut first = None;
        same_host_state(&mut first, "nokogiri-1.18.10", HOST.into()).unwrap();
        same_host_state(&mut first, "sqlite3-2.7.0", HOST.into()).unwrap();
        let error = same_host_state(&mut first, "pg-1.6.0", "2".repeat(64)).unwrap_err();
        assert!(
            error.to_string().contains("during the build of pg-1.6.0"),
            "{error}"
        );
        assert_eq!(first.as_deref(), Some(HOST));
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
        assert_eq!(
            message,
            "the build against this machine's whole /usr failed (sandboxed command \
             failed: second), after the build against the C runtime alone failed \
             (sandboxed command failed: first)"
        );
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
            fn() -> io::Result<String>,
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
                fingerprint: || Ok(HOST.to_string()),
                build: move |view| {
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
        assert_eq!(used_host.as_deref(), Some(HOST));
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
        assert_eq!(used_host, None, "the only attempt is no fallback");
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

//! Building against the host's C runtime alone first, and against the whole
//! host only when that fails (issue #304): the retry, the identity a
//! fallback object is committed under, and the store record that points a
//! later sync at it. Ruby native gems, Python sdists with native code and
//! npm packages with install scripts all build this way on Linux (#328).
//!
//! A fallback is a `host-build-inputs` exception, recorded before the
//! second attempt runs, so a policy that denies the kind stops with nothing
//! built against the host. The object it produces is committed under its
//! own identity, keyed by the host build inputs fingerprint
//! (`hostview::host_build_inputs`) the fallback was built against, so it
//! never answers for the runtime-only identity.

use crate::kernel::activity::StoreActivity;
use crate::kernel::sandbox::HostView;
use crate::kernel::store::Store;
use crate::kernel::types::Identity;
use crate::kernel::ui;
use std::io;

/// The `build_view` input of an identity whose native builds ran against
/// the C runtime alone.
// /3 invalidates builds that could link a lone lib*.so name before
// hostview curated such directories outside the plugin allowlist (#559).
pub(crate) const RUNTIME_ONLY_VIEW: &str = "runtime-only/3";
/// The `build_view` input of an identity where at least one build fell
/// back to the whole host.
pub(crate) const HOST_FALLBACK_VIEW: &str = "host-fallback/1";

/// A build against the whole host ran while the host's build inputs
/// changed (the fingerprints taken before and after it differ), or two
/// builds of one object fell back against different host states. Nothing
/// built in that sync can be keyed by one host state, so it fails.
#[derive(Debug)]
pub(crate) struct HostChanged(pub(crate) String);

impl std::fmt::Display for HostChanged {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "host development files changed during the build of {}; re-run tog",
            self.0
        )
    }
}

impl std::error::Error for HostChanged {}

/// Whether `error` is a `HostChanged`, which callers pass on unwrapped.
pub(crate) fn is_host_changed(error: &io::Error) -> bool {
    error
        .get_ref()
        .is_some_and(|inner| inner.is::<HostChanged>())
}

/// The one host state every fallback of an object was built against: the
/// first fallback's fingerprint, which each later one must equal.
pub(crate) fn same_host_state(
    first: &mut Option<String>,
    subject: &str,
    fingerprint: String,
) -> io::Result<()> {
    match first {
        None => *first = Some(fingerprint),
        Some(first) if *first != fingerprint => {
            return Err(io::Error::other(HostChanged(subject.to_string())))
        }
        Some(_) => {}
    }
    Ok(())
}

/// The identity an object is committed under when the `fell_back` builds
/// in it ran against the whole host: the runtime-only identity, with the
/// view renamed, the fallen-back names listed, and the fingerprint of the
/// host state they were built against (`host_inputs`). Two hosts, or one
/// host before and after a development package changed, get different
/// ids; the object never answers for the runtime-only identity.
pub(crate) fn fallback_identity(
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

/// An object `FallbackRecords::cached_object` found: its id, and when it
/// is a host-fallback object, the host build inputs it was built against.
pub(crate) struct CachedObject {
    pub(crate) id: String,
    pub(crate) host_inputs: Option<String>,
}

/// Where one kind of object records its fallbacks: the store record kind,
/// which names a recorded fallback must have to be believed, and what a
/// note about a failed write calls the builds.
pub(crate) struct FallbackRecords {
    /// The store record kind (`ruby-gems-host-fallback`).
    pub(crate) kind: &'static str,
    /// Whether a recorded name belongs to the runtime-only identity.
    pub(crate) names: fn(&Identity, &str) -> bool,
    /// The builds, in a note: "gems", "sdist builds".
    pub(crate) what: &'static str,
}

impl FallbackRecords {
    /// A record's key: the runtime-only id and the host fingerprint, so a
    /// host in another state finds no record and builds.
    pub(crate) fn key(runtime_only: &Identity, host_inputs: &str) -> String {
        serde_json::json!([runtime_only.object_id(), host_inputs]).to_string()
    }

    /// The names a previous build of `runtime_only`, on a host whose build
    /// inputs had this fingerprint, rebuilt against the whole host, as its
    /// store record says. A record that names something outside the
    /// identity, or nothing, is ignored.
    fn recorded(
        &self,
        store: &Store,
        runtime_only: &Identity,
        host_inputs: &str,
    ) -> io::Result<Option<Vec<String>>> {
        let key = Self::key(runtime_only, host_inputs);
        let Some(value) = store.read_record(self.kind, &key)? else {
            return Ok(None);
        };
        let names: Option<Vec<String>> = value["host_fallback"].as_array().and_then(|names| {
            names
                .iter()
                .map(|name| name.as_str().map(str::to_string))
                .collect()
        });
        Ok(names.filter(|names| {
            !names.is_empty() && names.iter().all(|name| (self.names)(runtime_only, name))
        }))
    }

    /// The object already in the store for `identity`: the runtime-only
    /// object itself, or, when a build of it on a host in this host's
    /// state fell back, the host-fallback object that build committed.
    /// Rebuilding would only fall back again against the same host inputs,
    /// so the record stands in for the attempt. `fingerprint`
    /// (`hostview::host_build_inputs` in production) is taken only past the
    /// first check, so a runtime-only hit never pays for it, and it serves
    /// this lookup only: a build keys its object by the fingerprints taken
    /// around its own fallbacks.
    pub(crate) fn cached_object(
        &self,
        store: &Store,
        activity: &StoreActivity,
        identity: &Identity,
        fingerprint: impl FnOnce() -> io::Result<String>,
    ) -> io::Result<Option<CachedObject>> {
        let id = identity.object_id();
        if store.has_with_activity(activity, &id)? {
            return Ok(Some(CachedObject {
                id,
                host_inputs: None,
            }));
        }
        if identity.inputs.get("build_view").map(String::as_str) != Some(RUNTIME_ONLY_VIEW) {
            return Ok(None);
        }
        let host_inputs = fingerprint()?;
        let Some(fell_back) = self.recorded(store, identity, &host_inputs)? else {
            return Ok(None);
        };
        let fallback = fallback_identity(identity, &fell_back, &host_inputs).object_id();
        Ok(store
            .has_with_activity(activity, &fallback)?
            .then_some(CachedObject {
                id: fallback,
                host_inputs: Some(host_inputs),
            }))
    }

    /// Record which builds of `runtime_only` fell back against these host
    /// inputs, so the next sync over the same store on a host in the same
    /// state finds the host-fallback object instead of building again. A
    /// failed write costs that sync a rebuild and nothing else, so it is
    /// reported and the sync goes on.
    pub(crate) fn record(
        &self,
        store: &Store,
        activity: &StoreActivity,
        runtime_only: &Identity,
        host_inputs: &str,
        fell_back: &[String],
    ) {
        let value = serde_json::json!({ "host_fallback": sorted(fell_back) });
        let key = Self::key(runtime_only, host_inputs);
        if let Err(error) = store.write_record(activity, self.kind, &key, &value) {
            ui::note(&format!(
                "{} built against the whole host were not recorded in the store ({error}); \
                 the next sync builds them again",
                self.what
            ));
        }
    }
}

/// One build as `hermetic_first` drives it: `record` records an exception,
/// `discard` undoes what a failed hermetic attempt left behind (or
/// refuses), `fingerprint` takes the host build inputs fingerprint
/// (`hostview::host_build_inputs`), and `build` runs one attempt with a
/// view.
pub(crate) struct Attempt<R, D, F, B> {
    pub(crate) record: R,
    pub(crate) discard: D,
    pub(crate) fingerprint: F,
    pub(crate) build: B,
}

/// Build `subject` against the host's C runtime alone, and only if that
/// build fails, against the whole host, saying in the `host-build-inputs`
/// exception `detail` why. The fallback is recorded before the second
/// attempt runs, so a policy that denies `host-build-inputs` stops here
/// with nothing built against the host.
///
/// A sandbox that could not be set up, or a run tog was asked to stop,
/// says nothing about the build and is returned as is.
///
/// Before the retry, `discard` removes what the failed attempt left
/// behind; a refusal records nothing.
///
/// The host build inputs are fingerprinted immediately before the retry
/// and again right after it. The fallback returns that fingerprint, the
/// host state the object was actually built against; when the two differ
/// the host changed under the build and it fails (`HostChanged`).
pub(crate) fn hermetic_first<R, D, F, B>(
    subject: &str,
    detail: &str,
    mut attempt: Attempt<R, D, F, B>,
) -> io::Result<Option<String>>
where
    R: FnOnce(&str, &str, &str) -> io::Result<()>,
    D: FnOnce() -> io::Result<()>,
    F: FnMut() -> io::Result<String>,
    B: FnMut(HostView) -> io::Result<()>,
{
    let hermetic = match (attempt.build)(HostView::RuntimeOnly) {
        Ok(()) => return Ok(None),
        Err(error) => error,
    };
    if matches!(
        hermetic.kind(),
        io::ErrorKind::Unsupported | io::ErrorKind::Interrupted
    ) {
        return Err(hermetic);
    }
    let attempts = format!("the build against the C runtime alone failed ({hermetic})");
    let prepared = (attempt.discard)().and_then(|()| {
        let before = (attempt.fingerprint)()?;
        (attempt.record)(crate::kernel::policy::HOST_BUILD_INPUTS, subject, detail)?;
        Ok(before)
    });
    let before = prepared.map_err(|refusal| {
        crate::kernel::error::context(
            refusal,
            format_args!("{attempts}, and it was not retried against the whole host"),
        )
    })?;
    // The retry's error first: it is the one left to fix, and a caller
    // that cuts the message short (an exception detail) keeps it.
    (attempt.build)(HostView::Full).map_err(|full| {
        io::Error::new(
            full.kind(),
            format!(
                "the build against this machine's whole /usr failed ({full}), after \
                 the build against the C runtime alone failed ({hermetic})"
            ),
        )
    })?;
    let after = (attempt.fingerprint)()?;
    if after != before {
        return Err(io::Error::other(HostChanged(subject.to_string())));
    }
    Ok(Some(after))
}

/// A `host-fallback/1` object names the builds that fell back, each one
/// that `belongs` accepts as a build of the object, sorted and without repeats, and the SHA-256 fingerprint
/// of the host build inputs they were built against; no other object
/// names either.
pub(crate) fn identity_contract(
    identity: &Identity,
    belongs: impl Fn(&str) -> bool,
) -> Result<(), String> {
    let view = identity.inputs.get("build_view").map(String::as_str);
    let fallback = view == Some("host-fallback/1");
    match identity.inputs.get("host_inputs") {
        Some(host_inputs) if !fallback => {
            return Err(format!(
                "host_inputs {host_inputs:?} without build_view host-fallback/1"
            ))
        }
        Some(host_inputs)
            if host_inputs.len() != 64
                || !host_inputs
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) =>
        {
            return Err(format!(
                "host_inputs {host_inputs:?} is not a lowercase SHA-256 hex digest"
            ))
        }
        None if fallback => {
            return Err("build_view host-fallback/1 without host_inputs".to_string())
        }
        _ => {}
    }
    let names = identity.inputs.get("host_fallback");
    match (view, names) {
        (Some("host-fallback/1"), Some(names)) => {
            let names: Vec<&str> = names.split(',').collect();
            if names.windows(2).any(|pair| pair[0] >= pair[1]) {
                return Err(format!("host_fallback {names:?} is not sorted and unique"));
            }
            for name in names {
                if !belongs(name) {
                    return Err(format!(
                        "host_fallback names {name:?}, which is not a build of this object"
                    ));
                }
            }
            Ok(())
        }
        (Some("host-fallback/1"), None) => {
            Err("build_view host-fallback/1 without host_fallback".to_string())
        }
        (_, Some(_)) => Err("host_fallback without build_view host-fallback/1".to_string()),
        (_, None) => Ok(()),
    }
}

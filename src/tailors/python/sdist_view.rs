//! Which host view an sdist build runs in. On Linux a build that compiles
//! native code tries the host's C runtime alone first and falls back to the
//! whole host only when that fails (`kernel::hostfallback`, #328); the
//! identity's `build_view` input says which builds do. The headers and
//! libraries a runtime-only build sees are the same on every host with the
//! same C runtime. One that needs more records `host-build-inputs` and is
//! committed under `hostfallback::fallback_identity`, never under the
//! runtime-only id. The environment holding such a wheel is keyed the same
//! way (`env::realize_artifacts`).

use super::build_requires::{self, ArchiveInfo};
use crate::kernel::activity::StoreActivity;
use crate::kernel::fetch::download_verified_held;
use crate::kernel::hostfallback::{
    self, Attempt, CachedObject, FallbackRecords, RUNTIME_ONLY_VIEW,
};
use crate::kernel::sandbox::HostView;
use crate::kernel::store::Store;
use crate::kernel::types::{Identity, LockedPackage};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Where a runtime-only sdist identity, built on a host in a given state,
/// records that its build fell back to the whole host. The one name it
/// holds is the package's.
const RECORDS: FallbackRecords = FallbackRecords {
    kind: "sdist-build-host-fallback",
    names: |identity, name| identity.name == name,
    what: "sdist builds",
};

/// What a `host-build-inputs` exception says about an sdist.
const HOST_BUILD_INPUTS_DETAIL: &str = "native code did not build against the C runtime \
     alone; rebuilt against this machine's development headers and libraries, so the wheel \
     depends on which -dev packages the host has";

/// A wheel built from an sdist, and when its build fell back to the whole
/// host, the host build inputs fingerprint it was built against.
#[derive(Debug)]
pub(crate) struct SdistWheel {
    pub(crate) path: PathBuf,
    pub(crate) host_inputs: Option<String>,
}

/// The sdist object already in the store for `identity`: the runtime-only
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

/// Run the build in the view `identity` asks for: against the C runtime
/// alone first when its `build_view` is runtime-only, with `discard`
/// undoing a failed attempt before the retry against the whole host;
/// against the whole host once otherwise. When it fell back, the host build
/// inputs fingerprint it was built against.
pub(super) fn build_in_view(
    identity: &Identity,
    pkg: &LockedPackage,
    mut build: impl FnMut(HostView) -> io::Result<()>,
    discard: impl FnOnce() -> io::Result<()>,
) -> io::Result<Option<String>> {
    if identity.inputs.get("build_view").map(String::as_str) != Some(RUNTIME_ONLY_VIEW) {
        return build(HostView::Full).map(|()| None);
    }
    hostfallback::hermetic_first(
        &format!("{}=={}", pkg.name, pkg.version),
        HOST_BUILD_INPUTS_DETAIL,
        Attempt {
            record: crate::kernel::policy::record,
            discard,
            fingerprint: crate::kernel::hostview::host_build_inputs,
            build,
        },
    )
}

/// The identity the wheel is committed under. A build that fell back
/// recorded `host-build-inputs`, which the object carries; it is committed
/// under its own identity, keyed by the host build inputs it was built
/// against, never under the runtime-only one.
pub(super) fn commit_identity(
    identity: &Identity,
    pkg: &LockedPackage,
    host_inputs: Option<&str>,
) -> Identity {
    match host_inputs {
        None => identity.clone(),
        Some(host_inputs) => {
            hostfallback::fallback_identity(identity, std::slice::from_ref(&pkg.name), host_inputs)
        }
    }
}

/// After a fallback build committed, point a later sync on a host in the
/// same state at its object (`FallbackRecords::record`).
pub(super) fn record(
    store: &Store,
    activity: &StoreActivity,
    identity: &Identity,
    pkg: &LockedPackage,
    host_inputs: Option<&str>,
) {
    if let Some(host_inputs) = host_inputs {
        RECORDS.record(
            store,
            activity,
            identity,
            host_inputs,
            std::slice::from_ref(&pkg.name),
        );
    }
}

/// Undo what a failed build against the C runtime alone left in `work`,
/// so the retry starts where the first attempt did: an empty `outdir`, no
/// build log, and for a Rust sdist a freshly unpacked source tree (a
/// build script's cached probe of a missing library would otherwise fail
/// the retry too), with the `Cargo.lock` tog generated (`generated_lock`) written back.
#[allow(clippy::too_many_arguments)]
pub(super) fn discard_failed_attempt(
    store: &Store,
    activity: &StoreActivity,
    pkg: &LockedPackage,
    info: &ArchiveInfo,
    work: &Path,
    outdir: &Path,
    source: Option<&Path>,
    generated_lock: Option<&str>,
) -> io::Result<()> {
    let removed = |path: &Path| match crate::kernel::store::remove_tree(path) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => Err(io::Error::new(
            error.kind(),
            format!("remove the failed attempt's {}: {error}", path.display()),
        )),
        _ => Ok(()),
    };
    removed(outdir)?;
    fs::create_dir_all(outdir)?;
    match fs::remove_file(work.join("pip-build.log")) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error),
        _ => {}
    }
    if source.is_some() {
        let unpacked = work.join("source");
        removed(&unpacked)?;
        let sdist = download_verified_held(store, activity, &pkg.url, &pkg.sha256)?;
        let root = build_requires::extract_sdist_for(activity, &sdist, &unpacked, info)?;
        if source != Some(root.as_path()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "{}: the sdist unpacked to {} on the retry, not {}",
                    pkg.name,
                    root.display(),
                    source.unwrap_or(&root).display()
                ),
            ));
        }
        if let (Some(lock), Some(manifest)) = (generated_lock, &info.cargo_manifest) {
            fs::write(
                super::build::generated_cargo_lock_path(&root, Path::new(manifest)),
                lock,
            )?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::platform::Platform;

    const HOST: &str = "1111111111111111111111111111111111111111111111111111111111111111";

    fn runtime_only_case() -> Identity {
        super::super::build::live_identity_cases(Platform::X86_64UnknownLinuxGnu)
            .into_iter()
            .find(|identity| {
                identity.inputs.get("build_view").map(String::as_str) == Some(RUNTIME_ONLY_VIEW)
            })
            .expect("a Linux native sdist identity builds against the C runtime first")
    }

    fn package(name: &str) -> LockedPackage {
        LockedPackage {
            name: name.into(),
            version: "1.0.0".into(),
            filename: format!("{name}-1.0.0.tar.gz"),
            url: String::new(),
            sha256: "a".repeat(64),
            kind: crate::kernel::types::ArtifactKind::Sdist,
            git: None,
        }
    }

    #[test]
    fn a_fallback_wheel_names_its_own_package_and_nothing_else() {
        let identity = runtime_only_case();
        let pkg = package(&identity.name);
        let fallback = commit_identity(&identity, &pkg, Some(HOST));
        assert_ne!(fallback.object_id(), identity.object_id());
        assert_eq!(fallback.inputs["host_fallback"], identity.name);
        assert_eq!(
            crate::kernel::objmeta::check_identity_grammar(&fallback),
            Ok(())
        );
        assert_eq!(
            commit_identity(&identity, &pkg, None).object_id(),
            identity.object_id()
        );
        let foreign = hostfallback::fallback_identity(&identity, &["other".into()], HOST);
        assert!(crate::kernel::objmeta::check_identity_grammar(&foreign).is_err());
    }

    #[test]
    fn a_build_without_a_runtime_only_view_runs_once_against_the_whole_host() {
        let mut identity = runtime_only_case();
        identity.inputs.remove("build_view");
        let mut views = Vec::new();
        let built = build_in_view(
            &identity,
            &package(&identity.name),
            |view| {
                views.push(view);
                Ok(())
            },
            || panic!("nothing to discard"),
        );
        assert_eq!(built.unwrap(), None);
        assert_eq!(views, [HostView::Full]);
    }

    #[test]
    fn a_runtime_only_build_that_succeeds_never_sees_the_host() {
        let identity = runtime_only_case();
        let mut views = Vec::new();
        let built = build_in_view(
            &identity,
            &package(&identity.name),
            |view| {
                views.push(view);
                Ok(())
            },
            || panic!("nothing to discard"),
        );
        assert_eq!(built.unwrap(), None);
        assert_eq!(views, [HostView::RuntimeOnly]);
    }
}

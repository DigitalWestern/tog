//! Object kinds the Python tailor produces, with the identity grammar each
//! producer writes and how a legacy record's dependencies are recovered from
//! it (the `object-meta/2` adapters; REFACTOR.md Stage 3 step 4). Every
//! row is proven by the metadata goldens in `kernel/objmeta.rs`.

use crate::kernel::objmeta::{
    add_digest, add_object, artifact_sha256, input, Algo, Grammar, KindAdapter, MetaIndex, Record,
};
use crate::kernel::store::{self, ObjectDeps};

pub static KINDS: &[KindAdapter] = &[
    KindAdapter {
        kind: "cpython",
        schema: None,
        grammar: Grammar {
            required: &["artifact_sha256"],
            optional: &["platform"],
            groups: &[],
        },
        adapt: artifact_sha256,
    },
    KindAdapter {
        kind: "uv",
        schema: None,
        grammar: Grammar {
            required: &["artifact_sha256"],
            optional: &["platform"],
            groups: &[],
        },
        adapt: artifact_sha256,
    },
    KindAdapter {
        kind: "native-libs",
        schema: None,
        grammar: Grammar {
            required: &["platform", "manifest_sha256"],
            optional: &["store_root"],
            groups: &[],
        },
        adapt: native_libs,
    },
    KindAdapter {
        kind: "python-env",
        schema: Some("python-env/2"),
        grammar: Grammar {
            required: &["schema", "cpython"],
            optional: &["store_root", "native_libs"],
            groups: &[("pkg:", None)],
        },
        adapt: python_env_v2,
    },
    KindAdapter {
        kind: "sdist-build",
        schema: Some("sdist-build/2"),
        grammar: Grammar {
            required: &["schema", "sdist_sha256", "python", "platform", "toolchain"],
            optional: &[],
            groups: &[],
        },
        adapt: sdist_build_v2,
    },
    KindAdapter {
        kind: "sdist-build",
        schema: Some("sdist-build/3"),
        grammar: Grammar {
            required: &["schema", "sdist_sha256", "python", "platform", "build_env"],
            optional: &["rust", "vendor", "native_libs", "native_linker"],
            groups: &[],
        },
        adapt: sdist_build_v3,
    },
];

/// `native-libs`: the identity commits to a *digest of the package manifest*,
/// never to the individual library digests, so they cannot be read out of the
/// record. They are recovered only when the pinned table still hashes to the
/// recorded manifest digest — that is a verified match against the record's
/// own evidence, not a current-default guess. A libset from a different pin
/// set is unresolved.
///
/// The rejected first implementation instead matched the key name
/// `manifest_sha256` and emitted the manifest hash itself as a cache digest,
/// fabricating a digest for a file that never existed in the cache.
fn native_libs(record: &Record, _index: &MetaIndex) -> Result<ObjectDeps, String> {
    if record.identity.version != crate::tailors::python::nativelibs::NATIVE_LIBS_VERSION {
        return Err(format!(
            "libset version {} predates the pinned manifest this build knows (v{}); its library \
             digests are not recoverable from metadata",
            record.identity.version,
            crate::tailors::python::nativelibs::NATIVE_LIBS_VERSION
        ));
    }
    let recorded = input(record, "manifest_sha256")?;
    let platform_input = input(record, "platform")?;
    let platform = crate::kernel::platform::Platform::ALL
        .iter()
        .find(|platform| platform.triple() == platform_input)
        .ok_or_else(|| format!("unknown platform {platform_input}"))?;
    let manifest = crate::tailors::python::nativelibs::manifest_sha256(*platform)
        .map_err(|error| format!("no pinned library manifest for {platform_input}: {error}"))?;
    if manifest != recorded {
        return Err(format!(
            "the pinned library manifest for {platform_input} hashes to {manifest}, not the \
             recorded {recorded}; the library digests for this object are not recoverable"
        ));
    }
    let mut deps = ObjectDeps::new();
    for sha256 in crate::tailors::python::nativelibs::pinned_package_digests(*platform)
        .map_err(|error| format!("pinned library set: {error}"))?
    {
        add_digest(&mut deps, Algo::Sha256, &sha256, "pinned library")?;
    }
    Ok(deps)
}

/// `python-env/2`: CPython and the native library set are direct object ids.
/// A wheel contributes its sha256. An sdist contributes the **built wheel's
/// object**, which the entry names in one of two shipped spellings:
/// `Sdist:<sha256>:<object id>` for an isolated (`sdist-build/3`) build, and
/// `Sdist:<sha256>:sdist-build/2;toolchain:<digests>` for the historical
/// fast path, whose derivation fingerprint is not an object id and must be
/// matched against the `sdist-build/2` records in the store.
fn python_env_v2(record: &Record, index: &MetaIndex) -> Result<ObjectDeps, String> {
    let cpython = input(record, "cpython")?;
    let mut deps = ObjectDeps::new();
    add_object(&mut deps, cpython, index, "cpython")?;
    if let Some(native_libs) = record.identity.inputs.get("native_libs") {
        add_object(&mut deps, native_libs, index, "native_libs")?;
    }
    let cpython_record = index
        .get(cpython)
        .ok_or_else(|| format!("cpython names object {cpython}, which has no metadata"))?;
    let cpython_reference = format!(
        "{}:{}",
        cpython_record.identity.version,
        cpython_record
            .identity
            .inputs
            .get("artifact_sha256")
            .map(String::as_str)
            .unwrap_or_default()
    );
    let platform = cpython_record
        .identity
        .inputs
        .get("platform")
        .map(String::as_str)
        .unwrap_or_default();
    for (key, value) in &record.identity.inputs {
        let Some(name) = key.strip_prefix("pkg:") else {
            if !matches!(
                key.as_str(),
                "schema" | "store_root" | "cpython" | "native_libs"
            ) {
                return Err(format!("unexpected identity input {key}"));
            }
            continue;
        };
        if let Some(sha256) = value.strip_prefix("Wheel:") {
            add_digest(&mut deps, Algo::Sha256, sha256, &format!("wheel {name}"))?;
            continue;
        }
        let rest = value
            .strip_prefix("Sdist:")
            .ok_or_else(|| format!("package {name} entry {value:?} is neither Wheel nor Sdist"))?;
        let (sdist_sha256, derivation) = rest
            .split_once(':')
            .ok_or_else(|| format!("package {name} entry {value:?} has no derivation field"))?;
        if store::is_object_id(derivation) {
            add_object(&mut deps, derivation, index, &format!("sdist build {name}"))?;
            continue;
        }
        let toolchain = derivation
            .strip_prefix("sdist-build/2;toolchain:")
            .ok_or_else(|| {
                format!(
                    "package {name} names derivation {derivation:?}, which is neither an object id \
                     nor a known sdist-build fingerprint"
                )
            })?;
        // The fast-path fingerprint omits the package version, so the object
        // is found by matching every part the fingerprint does commit to.
        let built = index.unique(
            "sdist-build",
            &format!(
                "sdist-build/2 of {name} from sdist {sdist_sha256} with toolchain {toolchain}"
            ),
            |candidate| {
                candidate.schema_input() == Some("sdist-build/2")
                    && candidate.identity.name == name
                    && candidate
                        .identity
                        .inputs
                        .get("sdist_sha256")
                        .map(String::as_str)
                        == Some(sdist_sha256)
                    && candidate
                        .identity
                        .inputs
                        .get("toolchain")
                        .map(String::as_str)
                        == Some(toolchain)
                    && candidate.identity.inputs.get("python").map(String::as_str)
                        == Some(cpython_reference.as_str())
                    && candidate
                        .identity
                        .inputs
                        .get("platform")
                        .map(String::as_str)
                        == Some(platform)
            },
        )?;
        add_object(&mut deps, &built, index, &format!("sdist build {name}"))?;
    }
    Ok(deps)
}

/// The interpreter object named by an sdist build's `python` input, which is
/// a `<version>:<artifact sha256>` fingerprint rather than an object id.
fn cpython_for_sdist(record: &Record, index: &MetaIndex) -> Result<String, String> {
    let reference = input(record, "python")?;
    let (version, sha256) = reference
        .split_once(':')
        .ok_or_else(|| format!("python {reference:?} is not a <version>:<sha256> reference"))?;
    let platform = input(record, "platform")?;
    index.unique(
        "cpython",
        &format!("CPython {version} for {platform} built from artifact {sha256}"),
        |candidate| {
            candidate.schema_input().is_none()
                && candidate.identity.version == version
                && candidate
                    .identity
                    .inputs
                    .get("artifact_sha256")
                    .map(String::as_str)
                    == Some(sha256)
                && candidate
                    .identity
                    .inputs
                    .get("platform")
                    .map(String::as_str)
                    == Some(platform)
        },
    )
}

/// `sdist-build/2`: the historical non-isolated build. Its build environment
/// was never a separate object, so the toolchain wheels it installed are
/// named directly by the `toolchain` fingerprint — a comma-joined list of
/// their sha256s (`build::build_toolchain_fingerprint`).
fn sdist_build_v2(record: &Record, index: &MetaIndex) -> Result<ObjectDeps, String> {
    let mut deps = ObjectDeps::new();
    let cpython = cpython_for_sdist(record, index)?;
    add_object(&mut deps, &cpython, index, "python")?;
    add_digest(
        &mut deps,
        Algo::Sha256,
        input(record, "sdist_sha256")?,
        "sdist_sha256",
    )?;
    let toolchain = input(record, "toolchain")?;
    if toolchain.is_empty() {
        return Err("toolchain fingerprint is empty".to_string());
    }
    for sha256 in toolchain.split(',') {
        add_digest(&mut deps, Algo::Sha256, sha256, "build toolchain wheel")?;
    }
    for key in record.identity.inputs.keys() {
        if !matches!(
            key.as_str(),
            "schema" | "sdist_sha256" | "python" | "platform" | "toolchain"
        ) {
            return Err(format!("unexpected identity input {key}"));
        }
    }
    Ok(deps)
}

/// `sdist-build/3`: the isolated build. The build environment, and any Rust
/// toolchain, vendor tree and native library set, are direct object ids; the
/// interpreter is a fingerprint; the sdist tarball is the one cached artifact.
fn sdist_build_v3(record: &Record, index: &MetaIndex) -> Result<ObjectDeps, String> {
    let mut deps = ObjectDeps::new();
    let cpython = cpython_for_sdist(record, index)?;
    add_object(&mut deps, &cpython, index, "python")?;
    add_object(&mut deps, input(record, "build_env")?, index, "build_env")?;
    add_digest(
        &mut deps,
        Algo::Sha256,
        input(record, "sdist_sha256")?,
        "sdist_sha256",
    )?;
    for key in ["rust", "vendor", "native_libs"] {
        if let Some(id) = record.identity.inputs.get(key) {
            add_object(&mut deps, id, index, key)?;
        }
    }
    for key in record.identity.inputs.keys() {
        if !matches!(
            key.as_str(),
            "schema"
                | "sdist_sha256"
                | "python"
                | "platform"
                | "build_env"
                | "rust"
                | "vendor"
                | "native_libs"
                | "native_linker"
        ) {
            return Err(format!("unexpected identity input {key}"));
        }
    }
    Ok(deps)
}

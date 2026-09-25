//! Object kinds the Python tailor produces. Each row has a migration grammar
//! for legacy records and a separate live grammar for current commits, plus
//! the `object-meta/2` dependency adapter. Every row is proven by the metadata
//! goldens in `kernel/objmeta.rs`.

use crate::kernel::objmeta::{
    add_digest, add_object, artifact_sha256, input, platform_of, Algo, Grammar, KindAdapter,
    MetaIndex, Record,
};
use crate::kernel::store::{self, ObjectDeps};
use crate::kernel::types::Identity;

pub static KINDS: &[KindAdapter] = &[
    KindAdapter {
        kind: "cpython",
        schema: None,
        superseded_by: None,
        live_required: &["artifact_sha256", "platform"],
        live_optional: &[],
        legacy_only: &[],
        live_contract: None,
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
        superseded_by: None,
        live_required: &["artifact_sha256", "platform"],
        live_optional: &[],
        legacy_only: &[],
        live_contract: None,
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
        superseded_by: None,
        live_required: &["platform", "manifest_sha256", "store_root"],
        live_optional: &[],
        legacy_only: &[],
        live_contract: Some(native_libs_contract),
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
        superseded_by: Some("python-env/3"),
        live_required: &["schema", "store_root", "cpython"],
        live_optional: &["native_libs", "pkg:"],
        legacy_only: &[],
        live_contract: Some(python_env_contract),
        grammar: Grammar {
            required: &["schema", "cpython"],
            optional: &["store_root", "native_libs"],
            groups: &[("pkg:", None)],
        },
        adapt: python_env_v2,
    },
    KindAdapter {
        kind: "python-env",
        schema: Some("python-env/3"),
        superseded_by: None,
        live_required: &[
            "schema",
            "store_root",
            "cpython",
            "package_digest",
            "native",
        ],
        live_optional: &["native_libs", "pkg:"],
        legacy_only: &[],
        live_contract: Some(python_env_v3_contract),
        grammar: Grammar {
            required: &["schema", "cpython", "package_digest", "native"],
            optional: &["store_root", "native_libs"],
            groups: &[("pkg:", None)],
        },
        adapt: python_env_v3,
    },
    KindAdapter {
        kind: "sdist-build",
        schema: Some("sdist-build/2"),
        superseded_by: None,
        live_required: &["schema", "sdist_sha256", "python", "platform", "toolchain"],
        live_optional: &[],
        legacy_only: &[],
        live_contract: None,
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
        superseded_by: Some("sdist-build/4"),
        live_required: &["schema", "sdist_sha256", "python", "platform", "build_env"],
        live_optional: &["rust", "vendor", "native_libs", "native_linker"],
        legacy_only: &[],
        live_contract: Some(sdist_build_v3_contract),
        grammar: Grammar {
            required: &["schema", "sdist_sha256", "python", "platform", "build_env"],
            optional: &["rust", "vendor", "native_libs", "native_linker"],
            groups: &[],
        },
        adapt: sdist_build_v3,
    },
    KindAdapter {
        kind: "sdist-build",
        schema: Some("sdist-build/4"),
        superseded_by: None,
        live_required: &[
            "schema",
            "sdist_sha256",
            "python",
            "platform",
            "build_env",
            "build_mode",
            "native_mode",
        ],
        live_optional: &["rust", "vendor", "native_libs", "native_linker"],
        legacy_only: &[],
        live_contract: Some(sdist_build_v4_contract),
        grammar: Grammar {
            required: &[
                "schema",
                "sdist_sha256",
                "python",
                "platform",
                "build_env",
                "build_mode",
                "native_mode",
            ],
            optional: &["rust", "vendor", "native_libs", "native_linker"],
            groups: &[],
        },
        adapt: sdist_build_v4,
    },
];

fn native_libs_contract(identity: &Identity) -> Result<(), String> {
    let platform = platform_of(identity)?.ok_or_else(|| {
        "native-libs platform contract: the producer must record a platform input".to_string()
    })?;
    if platform != crate::kernel::platform::Platform::X86_64UnknownLinuxGnu {
        return Err(format!(
            "native-libs platform contract: no native-libs pin exists for {}",
            platform.triple()
        ));
    }
    Ok(())
}

/// `python-env/2` could not detect two identity drifts. A one-wheel plan
/// that dropped its sole `pkg:` key was indistinguishable from the
/// legitimate empty environment, and an inspected native sdist that dropped
/// its `native_libs` key passed, because every native check was conditional
/// on that key. `python-env/3` closes both; this row survives only for
/// records already in the store.
fn python_env_contract(identity: &Identity) -> Result<(), String> {
    let inputs = &identity.inputs;
    // An environment with no packages is legitimate. The producer writes no
    // pkg: key in that shape; native_libs is only possible with an inspected
    // native sdist package.
    if inputs.contains_key("native_libs") && !inputs.keys().any(|key| key.starts_with("pkg:")) {
        return Err(
            "Python environment native_libs/pkg relation: native_libs requires a pkg: input".into(),
        );
    }
    // Native library mounting is selected by real sdist inspection. A wheel
    // group can legitimately be empty, but native_libs must accompany an
    // sdist package rather than a hand-shaped wheel-only identity.
    if inputs.contains_key("native_libs")
        && !inputs
            .iter()
            .any(|(key, value)| key.starts_with("pkg:") && value.starts_with("Sdist:"))
    {
        return Err(
            "Python environment native_libs/pkg relation: native_libs requires an inspected Sdist: package"
                .into(),
        );
    }
    if let Some(native_libs) = inputs.get("native_libs") {
        let cpython = inputs.get("cpython").ok_or_else(|| {
            "Python environment native platform relation: no cpython input".to_string()
        })?;
        let cpython_platform =
            crate::kernel::platform::Platform::ALL
                .iter()
                .copied()
                .find(|platform| {
                    crate::tailors::python::object_id_for(*platform, &identity.version)
                        .map(|id| id == *cpython)
                        .unwrap_or(false)
                });
        if cpython_platform != Some(crate::kernel::platform::Platform::X86_64UnknownLinuxGnu) {
            return Err(format!(
                "Python environment native platform relation: native_libs {native_libs:?} is only produced for Linux CPython"
            ));
        }
    }
    Ok(())
}

/// `python-env/3` adds two unconditional inputs to the `/2` shape: a
/// `package_digest` over every `pkg:` entry, and a `native` decision the
/// producer spells out whether or not it mounts the library set. A dropped
/// sole `pkg:` key leaves a digest no package set produces, and a
/// dropped `native_libs` key leaves `native` claiming a mount that is not
/// there. Both are recomputed here from the producer's own functions.
fn python_env_v3_contract(identity: &Identity) -> Result<(), String> {
    // The `/2` relations run first: when one of them can name the exact
    // pairing that broke, that is a better diagnostic than "the digest moved".
    python_env_contract(identity)?;
    let inputs = &identity.inputs;
    let declared = inputs
        .get("package_digest")
        .ok_or_else(|| "Python environment package digest: no package_digest input".to_string())?;
    let recomputed = super::env::package_digest_of_inputs(inputs);
    if *declared != recomputed {
        return Err(format!(
            "Python environment package digest: package_digest {declared} does not match the \
             {recomputed} this package set hashes to"
        ));
    }
    let native = inputs
        .get("native")
        .ok_or_else(|| "Python environment native decision: no native input".to_string())?;
    let expected = match inputs.contains_key("native_libs") {
        true => super::env::NATIVE_LIBS_MOUNTED,
        false => super::env::NATIVE_NONE,
    };
    if native != expected {
        return Err(format!(
            "Python environment native decision: native {native:?} does not match the \
             {expected:?} this identity's native_libs input implies"
        ));
    }
    Ok(())
}

/// `sdist-build/3` could not detect either pair being dropped as a whole.
/// Dropping both `rust` and `vendor`, or both `native_libs` and
/// `native_linker`, left the same valid no-pair shape, because these checks
/// only reject one-sided pairs. `sdist-build/4` closes both with explicit
/// mode fields; this row survives only for records already in the store.
fn sdist_build_v3_contract(identity: &Identity) -> Result<(), String> {
    let platform = platform_of(identity)?.ok_or_else(|| {
        "Python sdist platform contract: the producer must record a platform input".to_string()
    })?;
    let has_native = identity.inputs.contains_key("native_libs");
    let has_linker = identity.inputs.contains_key("native_linker");
    if has_native != has_linker {
        return Err(
            "sdist native_libs/native_linker relation: native_libs and native_linker must appear together"
                .into(),
        );
    }
    if platform.is_macos() && (has_native || has_linker) {
        return Err(
            "sdist native platform relation: native_libs and native_linker are Linux-only".into(),
        );
    }
    for (left, right, relation) in [("rust", "vendor", "sdist Rust/vendor relation")] {
        if identity.inputs.contains_key(left) != identity.inputs.contains_key(right) {
            return Err(format!(
                "{relation}: {left} and {right} must appear together"
            ));
        }
    }
    Ok(())
}

/// `sdist-build/4` adds the two unconditional mode fields. `build_mode` says
/// whether this build had a Rust toolchain and vendor tree, and
/// `native_mode` whether it mounted the native library set, so dropping a
/// whole pair never collapses into the valid shape that never had one.
fn sdist_build_v4_contract(identity: &Identity) -> Result<(), String> {
    sdist_build_v3_contract(identity)?;
    let inputs = &identity.inputs;
    for (field, key, present, absent) in [
        (
            "build_mode",
            "rust",
            super::build::BUILD_MODE_RUST,
            super::build::BUILD_MODE_PLAIN,
        ),
        (
            "native_mode",
            "native_libs",
            super::build::NATIVE_MODE_LIBS,
            super::build::NATIVE_MODE_NONE,
        ),
    ] {
        let declared = inputs
            .get(field)
            .ok_or_else(|| format!("sdist {field} relation: no {field} input"))?;
        let expected = match inputs.contains_key(key) {
            true => present,
            false => absent,
        };
        if declared != expected {
            return Err(format!(
                "sdist {field} relation: {field} {declared:?} does not match the {expected:?} \
                 this identity's {key} input implies"
            ));
        }
    }
    Ok(())
}

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
    if record.identity.version != crate::kernel::provider::nativelibs::NATIVE_LIBS_VERSION {
        return Err(format!(
            "libset version {} predates the pinned manifest this build knows (v{}); its library \
             digests are not recoverable from metadata",
            record.identity.version,
            crate::kernel::provider::nativelibs::NATIVE_LIBS_VERSION
        ));
    }
    let recorded = input(record, "manifest_sha256")?;
    let platform_input = input(record, "platform")?;
    let platform = crate::kernel::platform::Platform::ALL
        .iter()
        .find(|platform| platform.triple() == platform_input)
        .ok_or_else(|| format!("unknown platform {platform_input}"))?;
    let manifest = crate::kernel::provider::nativelibs::manifest_sha256(*platform)
        .map_err(|error| format!("no pinned library manifest for {platform_input}: {error}"))?;
    if manifest != recorded {
        return Err(format!(
            "the pinned library manifest for {platform_input} hashes to {manifest}, not the \
             recorded {recorded}; the library digests for this object are not recoverable"
        ));
    }
    let mut deps = ObjectDeps::new();
    for sha256 in crate::kernel::provider::nativelibs::pinned_package_digests(*platform)
        .map_err(|error| format!("pinned library set: {error}"))?
    {
        add_digest(&mut deps, Algo::Sha256, &sha256, "pinned library")?;
    }
    Ok(deps)
}

/// `python-env/2`: CPython and the native library set are direct object ids.
/// A wheel contributes its sha256. An sdist contributes the **built wheel's
/// object**, which the entry names in one of two shipped spellings:
/// `Sdist:<sha256>:<object id>` for an isolated build, and
/// `Sdist:<sha256>:sdist-build/2;toolchain:<digests>` for the historical
/// fast path, whose derivation fingerprint is not an object id and must be
/// matched against the `sdist-build/2` records in the store.
fn python_env_v2(record: &Record, index: &MetaIndex) -> Result<ObjectDeps, String> {
    python_env_inner(
        record,
        index,
        &["schema", "store_root", "cpython", "native_libs"],
    )
}

/// `python-env/3`: the same byte sources. `package_digest` and `native` are
/// drift guards over inputs that are already named here, so neither adds a
/// dependency of its own.
///
/// Every object of this schema was committed with explicit evidence,
/// so legacy migration cannot reach it in practice; the metadata
/// goldens in `kernel/objmeta.rs` are what exercise this adapter.
fn python_env_v3(record: &Record, index: &MetaIndex) -> Result<ObjectDeps, String> {
    python_env_inner(
        record,
        index,
        &[
            "schema",
            "store_root",
            "cpython",
            "native_libs",
            "package_digest",
            "native",
        ],
    )
}

fn python_env_inner(
    record: &Record,
    index: &MetaIndex,
    scalars: &[&str],
) -> Result<ObjectDeps, String> {
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
            if !scalars.contains(&key.as_str()) {
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
/// their sha256s (the toolchain fingerprint in `build::derivation_fingerprint`).
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
    sdist_build_isolated(
        record,
        index,
        &[
            "schema",
            "sdist_sha256",
            "python",
            "platform",
            "build_env",
            "rust",
            "vendor",
            "native_libs",
            "native_linker",
        ],
    )
}

/// `sdist-build/4`: the same byte sources as `/3`. `build_mode` and
/// `native_mode` restate decisions the object ids above already carry, so
/// neither adds a dependency.
///
/// Every object of this schema was committed with explicit evidence,
/// so legacy migration cannot reach it in practice; the metadata
/// goldens in `kernel/objmeta.rs` are what exercise this adapter.
fn sdist_build_v4(record: &Record, index: &MetaIndex) -> Result<ObjectDeps, String> {
    sdist_build_isolated(
        record,
        index,
        &[
            "schema",
            "sdist_sha256",
            "python",
            "platform",
            "build_env",
            "build_mode",
            "native_mode",
            "rust",
            "vendor",
            "native_libs",
            "native_linker",
        ],
    )
}

fn sdist_build_isolated(
    record: &Record,
    index: &MetaIndex,
    allowed: &[&str],
) -> Result<ObjectDeps, String> {
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
        if !allowed.contains(&key.as_str()) {
            return Err(format!("unexpected identity input {key}"));
        }
    }
    Ok(deps)
}

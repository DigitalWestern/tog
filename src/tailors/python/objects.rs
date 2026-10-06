//! Object kinds the Python tailor produces: one row per (kind, schema) pair,
//! naming the identity inputs its producer writes. Debug builds check every
//! commit against its row (`objmeta::check_identity_grammar`).

use crate::kernel::objmeta::{platform_of, ObjectKind};
use crate::kernel::types::Identity;

pub static KINDS: &[ObjectKind] = &[
    ObjectKind {
        kind: "python-env",
        schema: Some("python-env/3"),
        live_required: &[
            "schema",
            "store_root",
            "cpython",
            "package_digest",
            "native",
        ],
        live_optional: &[
            "native_libs",
            "build_view",
            "host_fallback",
            "host_inputs",
            "pkg:",
        ],
        live_contract: Some(python_env_v3_contract),
    },
    ObjectKind {
        kind: "sdist-build",
        schema: Some("sdist-build/2"),
        live_required: &["schema", "sdist_sha256", "python", "platform", "toolchain"],
        live_optional: &[],
        live_contract: None,
    },
    ObjectKind {
        kind: "sdist-build",
        schema: Some("sdist-build/4"),
        live_required: &[
            "schema",
            "sdist_sha256",
            "python",
            "platform",
            "build_env",
            "build_mode",
            "native_mode",
        ],
        live_optional: &[
            "rust",
            "vendor",
            "native_libs",
            "native_linker",
            "build_view",
            "host_fallback",
            "host_inputs",
        ],
        live_contract: Some(sdist_build_v4_contract),
    },
    ObjectKind {
        kind: "sdist-build",
        schema: Some("sdist-build/5"),
        live_required: &[
            "schema",
            "sdist_sha256",
            "python",
            "platform",
            "build_env",
            "build_mode",
            "native_mode",
            "rust_build_config",
        ],
        live_optional: &[
            "rust",
            "vendor",
            "native_libs",
            "native_linker",
            "build_view",
            "host_fallback",
            "host_inputs",
        ],
        live_contract: Some(sdist_build_v5_contract),
    },
];

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
    // A host-fallback environment names the sdists whose wheels fell back.
    crate::kernel::hostfallback::identity_contract(identity, |name| {
        identity.inputs.contains_key(&format!("pkg:{name}"))
    })?;
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
    // A host-fallback wheel names its own package as what fell back.
    crate::kernel::hostfallback::identity_contract(identity, |name| name == identity.name)?;
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

/// Rust builds add a versioned flag configuration. Plain builds retain /4
/// and its historical identities, and existing /4 Rust records stay readable.
fn sdist_build_v5_contract(identity: &Identity) -> Result<(), String> {
    sdist_build_v4_contract(identity)?;
    if identity.inputs.get("build_mode").map(String::as_str) != Some(super::build::BUILD_MODE_RUST)
    {
        return Err("sdist Rust build configuration: schema /5 requires a Rust build".into());
    }
    if identity.inputs.get("rust_build_config").map(String::as_str)
        != Some(super::build::RUST_BUILD_CONFIG)
    {
        return Err("sdist Rust build configuration: unsupported rust_build_config".into());
    }
    Ok(())
}

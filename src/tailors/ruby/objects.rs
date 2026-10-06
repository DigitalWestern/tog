//! Object kinds the Ruby tailor produces: one row per (kind, schema) pair,
//! naming the identity inputs its producer writes. Debug builds check every
//! commit against its row (`objmeta::check_identity_grammar`).

use crate::kernel::objmeta::ObjectKind;
use crate::kernel::types::Identity;

pub static KINDS: &[ObjectKind] = &[
    ObjectKind {
        kind: "ruby",
        schema: Some("ruby-toolchain/1"),
        live_required: &["schema", "artifact_sha256", "platform"],
        live_optional: &[],
        live_contract: None,
    },
    ObjectKind {
        kind: "ruby-gems",
        schema: Some("ruby-gems/1"),
        live_required: &["schema", "installer", "ruby_platform"],
        live_optional: &[
            "build_view",
            "native",
            "native_libs",
            "host_fallback",
            "host_inputs",
            "gem:",
        ],
        live_contract: Some(ruby_gems_contract),
    },
];

/// Empty gem plans are legitimate. Otherwise the producer stores the exact
/// gem count in identity.version, so a dropped gem key cannot become an
/// indistinguishable empty or partial object.
fn ruby_gems_contract(identity: &Identity) -> Result<(), String> {
    let gems = identity
        .inputs
        .keys()
        .filter(|key| key.starts_with("gem:"))
        .count();
    let version = identity.version.parse::<usize>().map_err(|_| {
        format!(
            "Ruby gem count/version relation: version {:?} is not a count for {gems} gem: inputs",
            identity.version
        )
    })?;
    if version != gems {
        return Err(format!(
            "Ruby gem count/version relation: version {version} does not match {gems} gem: inputs"
        ));
    }
    crate::kernel::hostfallback::identity_contract(identity, |name| {
        identity.inputs.contains_key(&format!("gem:{name}"))
    })?;
    native_contract(identity)
}

/// A Linux gems object (one with a `build_view`) spells out whether its
/// native gems built with tog's native library set (`native`), and names
/// the set exactly when they did; a macOS one names neither. A plan with
/// no gem has no native gem.
fn native_contract(identity: &Identity) -> Result<(), String> {
    let inputs = &identity.inputs;
    let linux = inputs.contains_key("build_view");
    let native = inputs.get("native").map(String::as_str);
    let has_libs = inputs.contains_key("native_libs");
    if !linux {
        return match (native, has_libs) {
            (None, false) => Ok(()),
            _ => Err("Ruby native decision: native and native_libs are Linux-only".into()),
        };
    }
    let expected = match has_libs {
        true => super::native_libs::NATIVE_LIBS_MOUNTED,
        false => super::native_libs::NATIVE_NONE,
    };
    if native != Some(expected) {
        return Err(format!(
            "Ruby native decision: native {native:?} does not match the {expected:?} this \
             identity's native_libs input implies"
        ));
    }
    if has_libs && !inputs.keys().any(|key| key.starts_with("gem:")) {
        return Err("Ruby native_libs/gem relation: native_libs requires a gem: input".into());
    }
    Ok(())
}

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
        live_optional: &["build_view", "host_fallback", "host_inputs", "gem:"],
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
    })
}

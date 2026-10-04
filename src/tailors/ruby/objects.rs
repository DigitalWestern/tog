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
    host_fallback_contract(identity)
}

/// A `host-fallback/1` object names the gems that fell back, each one a gem
/// of the object, sorted and without repeats, and the SHA-256 fingerprint
/// of the host build inputs they were built against; no other object
/// names either.
fn host_fallback_contract(identity: &Identity) -> Result<(), String> {
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
                if !identity.inputs.contains_key(&format!("gem:{name}")) {
                    return Err(format!(
                        "host_fallback names {name:?}, which is not a gem: input"
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

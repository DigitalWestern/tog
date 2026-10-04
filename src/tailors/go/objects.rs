//! Object kinds the Go tailor produces: one row per (kind, schema) pair,
//! naming the identity inputs its producer writes. Debug builds check every
//! commit against its row (`objmeta::check_identity_grammar`).

use crate::kernel::objmeta::ObjectKind;
use crate::kernel::types::Identity;

pub static KINDS: &[ObjectKind] = &[
    ObjectKind {
        kind: "go",
        schema: Some("go-toolchain/1"),
        live_required: &["schema", "artifact_sha256", "platform"],
        live_optional: &[],
        live_contract: None,
    },
    ObjectKind {
        kind: "go-modcache",
        schema: Some("go-modcache/1"),
        live_required: &["schema", "extractor"],
        live_optional: &["mod:", "modfile:", "info:"],
        live_contract: Some(go_module_contract),
    },
];

fn go_module_contract(identity: &Identity) -> Result<(), String> {
    let inputs = &identity.inputs;
    // Empty module caches are legitimate. The producer records zero in
    // identity.version, and every module contributes one complete triplet.
    let counts = ["mod:", "modfile:", "info:"]
        .map(|prefix| inputs.keys().filter(|key| key.starts_with(prefix)).count());
    let version = identity.version.parse::<usize>().map_err(|_| {
        format!(
            "Go module count/version relation; Go module triplet relation: version {:?} is not a count for mod:/modfile:/info: triplets",
            identity.version
        )
    })?;
    if counts.iter().any(|count| *count != version)
        || counts[0] != counts[1]
        || counts[0] != counts[2]
    {
        return Err(format!(
            "Go module count/version relation; Go module triplet relation: version {version}, mod:/modfile:/info: counts are {counts:?}"
        ));
    }
    for (prefix, siblings) in [
        ("mod:", ["modfile:", "info:"]),
        ("modfile:", ["mod:", "info:"]),
        ("info:", ["mod:", "modfile:"]),
    ] {
        for key in inputs.keys().filter(|key| key.starts_with(prefix)) {
            let suffix = &key[prefix.len()..];
            for sibling in siblings {
                let sibling_key = format!("{sibling}{suffix}");
                if !inputs.contains_key(&sibling_key) {
                    return Err(format!(
                        "Go module triplet relation: {key} requires {sibling_key}"
                    ));
                }
            }
        }
    }
    Ok(())
}

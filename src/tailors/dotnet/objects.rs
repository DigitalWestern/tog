//! Object kinds the .NET tailor produces: one row per (kind, schema) pair,
//! naming the identity inputs its producer writes. Debug builds check every
//! commit against its row (`objmeta::check_identity_grammar`).

use crate::kernel::objmeta::ObjectKind;
use crate::kernel::types::Identity;

pub static KINDS: &[ObjectKind] = &[
    ObjectKind {
        kind: "dotnet-sdk",
        schema: Some("dotnet-sdk/1"),
        live_required: &["schema", "artifact_sha512", "platform"],
        live_optional: &[],
        live_contract: None,
    },
    ObjectKind {
        kind: "nuget-packages",
        schema: Some("nuget-packages/1"),
        live_required: &["schema", "extractor"],
        live_optional: &["pkg:", "raw:"],
        live_contract: Some(nuget_package_contract),
    },
];

fn nuget_package_contract(identity: &Identity) -> Result<(), String> {
    let inputs = &identity.inputs;
    // Empty restore plans are legitimate. The producer records zero in
    // identity.version, and every package contributes one pkg:/raw: pair.
    let pkg = identity
        .inputs
        .keys()
        .filter(|key| key.starts_with("pkg:"))
        .count();
    let raw = identity
        .inputs
        .keys()
        .filter(|key| key.starts_with("raw:"))
        .count();
    let version = identity.version.parse::<usize>().map_err(|_| {
        format!(
            "NuGet package count/version relation; NuGet pkg/raw relation: version {:?} is not a count for {pkg} pkg:/raw: pairs",
            identity.version
        )
    })?;
    if pkg != raw || version != pkg {
        return Err(format!(
            "NuGet package count/version relation; NuGet pkg/raw relation: version {version}, pkg: count {pkg}, raw: count {raw}"
        ));
    }
    for (prefix, sibling) in [("pkg:", "raw:"), ("raw:", "pkg:")] {
        for key in inputs.keys().filter(|key| key.starts_with(prefix)) {
            let suffix = &key[prefix.len()..];
            let sibling_key = format!("{sibling}{suffix}");
            if !inputs.contains_key(&sibling_key) {
                return Err(format!(
                    "NuGet pkg/raw relation: {key} requires {sibling_key}"
                ));
            }
        }
    }
    Ok(())
}

//! Object kinds the .NET tailor produces. Each row has a migration grammar
//! for legacy records and a separate live grammar for current commits, plus
//! the `object-meta/2` dependency adapter. Every row is proven by the metadata
//! goldens in `kernel/objmeta.rs`.

use crate::kernel::objmeta::{
    add_digest, add_object, artifact_sha512, input, Algo, Grammar, KindAdapter, MetaIndex, Record,
};
use crate::kernel::store::ObjectDeps;
use std::collections::BTreeMap;

pub static KINDS: &[KindAdapter] = &[
    KindAdapter {
        kind: "dotnet-sdk",
        schema: Some("dotnet-sdk/1"),
        live_required: &["schema", "artifact_sha512", "platform"],
        live_optional: &[],
        live_relations: None,
        grammar: Grammar {
            required: &["schema", "artifact_sha512"],
            optional: &["platform"],
            groups: &[],
        },
        adapt: artifact_sha512,
    },
    KindAdapter {
        kind: "nuget-packages",
        schema: Some("nuget-packages/1"),
        live_required: &["schema", "extractor"],
        live_optional: &["pkg:", "raw:"],
        live_relations: Some(nuget_package_relations),
        grammar: Grammar {
            required: &["schema", "extractor"],
            optional: &[],
            // NuGet always writes the pkg/raw pair per package; `pkg:` is
            // NuGet's own content hash (not a cache address) and `raw:` is
            // the cached `.nupkg` digest. Either alone is a truncated record.
            groups: &[("raw:", Some(&["pkg:"])), ("pkg:", Some(&["raw:"]))],
        },
        adapt: nuget_packages,
    },
];

fn nuget_package_relations(inputs: &BTreeMap<String, String>) -> Result<(), String> {
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

/// `nuget-packages/1`: the extractor is the SDK object id itself. `pkg:` holds
/// NuGet's own base64 content hash, which is not a cache address; `raw:` holds
/// the sha256 of the cached `.nupkg`, which is.
fn nuget_packages(record: &Record, index: &MetaIndex) -> Result<ObjectDeps, String> {
    let mut deps = ObjectDeps::new();
    add_object(&mut deps, input(record, "extractor")?, index, "extractor")?;
    for (key, value) in &record.identity.inputs {
        if let Some(package) = key.strip_prefix("raw:") {
            add_digest(
                &mut deps,
                Algo::Sha256,
                value,
                &format!("package {package}"),
            )?;
        } else if !key.starts_with("pkg:") && key != "schema" && key != "extractor" {
            return Err(format!("unexpected identity input {key}"));
        }
    }
    Ok(deps)
}

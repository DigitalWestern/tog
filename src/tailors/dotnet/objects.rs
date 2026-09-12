//! Object kinds the .NET tailor produces, with the identity grammar each
//! producer writes and how a legacy record's dependencies are recovered from
//! it (the `object-meta/2` adapters; REFACTOR.md Stage 3 step 4). Every
//! row is proven by the metadata goldens in `kernel/objmeta.rs`.

use crate::kernel::objmeta::{
    add_digest, add_object, artifact_sha512, input, Algo, Grammar, KindAdapter, MetaIndex, Record,
};
use crate::kernel::store::ObjectDeps;

pub static KINDS: &[KindAdapter] = &[
    KindAdapter {
        kind: "dotnet-sdk",
        schema: Some("dotnet-sdk/1"),
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

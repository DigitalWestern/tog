//! Object kinds the Node tailor produces, with the identity grammar each
//! producer writes and how a legacy record's dependencies are recovered from
//! it (the `object-meta/2` adapters; REFACTOR.md Stage 3 step 4). Every
//! row is proven by the metadata goldens in `kernel/objmeta.rs`.

use crate::kernel::objmeta::{
    add_digest, add_object, artifact_sha256, input, parse_digest, Algo, Grammar, KindAdapter,
    MetaIndex, Record,
};
use crate::kernel::store::ObjectDeps;

pub static KINDS: &[KindAdapter] = &[
    KindAdapter {
        kind: "nodejs",
        schema: None,
        grammar: Grammar {
            required: &["artifact_sha256"],
            optional: &["platform"],
            groups: &[],
        },
        adapt: artifact_sha256,
    },
    KindAdapter {
        kind: "node-env",
        schema: Some("node-env/3"),
        grammar: Grammar {
            required: &["schema", "nodejs"],
            optional: &["store_root", "layout", "workspaces", "native_libs"],
            groups: &[("pkg:", None), ("provisioned:", None), ("artifact:", None)],
        },
        adapt: node_env_v3,
    },
];

/// `node-env/3`: Node and the native library set are direct object ids; a
/// registry package contributes the SRI digest embedded in its `pkg:` entry
/// (in the algorithm npm published, which may be sha1, sha256 or sha512); a
/// git package contributes its realized `git-source` object.
fn node_env_v3(record: &Record, index: &MetaIndex) -> Result<ObjectDeps, String> {
    let mut deps = ObjectDeps::new();
    add_object(&mut deps, input(record, "nodejs")?, index, "nodejs")?;
    if let Some(native_libs) = record.identity.inputs.get("native_libs") {
        add_object(&mut deps, native_libs, index, "native_libs")?;
    }
    for (key, value) in &record.identity.inputs {
        if let Some(path) = key.strip_prefix("pkg:") {
            match value.strip_prefix("git:") {
                Some(rest) => {
                    let (id, _) = rest.split_once(':').ok_or_else(|| {
                        format!("package {path} git entry {value:?} has no name field")
                    })?;
                    add_object(&mut deps, id, index, &format!("package {path}"))?;
                }
                None => {
                    // "<algo>:<hex>:<name>@<version>:patch[..]:bin[..]"
                    let (algo, rest) = value.split_once(':').ok_or_else(|| {
                        format!("package {path} entry {value:?} has no integrity algorithm")
                    })?;
                    let (hex, _) = rest.split_once(':').ok_or_else(|| {
                        format!("package {path} entry {value:?} has no integrity digest")
                    })?;
                    let digest = parse_digest(algo, hex)
                        .map_err(|reason| format!("package {path}: {reason}"))?;
                    deps.cache_digest(digest);
                }
            }
        } else if let Some(path) = key.strip_prefix("provisioned:") {
            let (_, sha256) = value.rsplit_once(':').ok_or_else(|| {
                format!("provisioned artifact {path} entry {value:?} has no sha256")
            })?;
            add_digest(
                &mut deps,
                Algo::Sha256,
                sha256,
                &format!("provisioned {path}"),
            )?;
        } else if let Some(path) = key.strip_prefix("artifact:") {
            add_digest(&mut deps, Algo::Sha256, value, &format!("artifact {path}"))?;
        } else if !matches!(
            key.as_str(),
            "schema" | "store_root" | "nodejs" | "layout" | "workspaces" | "native_libs"
        ) {
            return Err(format!("unexpected identity input {key}"));
        }
    }
    Ok(deps)
}

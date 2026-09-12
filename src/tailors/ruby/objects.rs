//! Object kinds the Ruby tailor produces, with the identity grammar each
//! producer writes and how a legacy record's dependencies are recovered from
//! it (the `object-meta/2` adapters; REFACTOR.md Stage 3 step 4). Every
//! row is proven by the metadata goldens in `kernel/objmeta.rs`.

use crate::kernel::objmeta::{
    add_digest, add_object, artifact_sha256, input, Algo, Grammar, KindAdapter, MetaIndex, Record,
};
use crate::kernel::store::ObjectDeps;

pub static KINDS: &[KindAdapter] = &[
    KindAdapter {
        kind: "ruby",
        schema: Some("ruby-toolchain/1"),
        grammar: Grammar {
            required: &["schema", "artifact_sha256"],
            optional: &["platform"],
            groups: &[],
        },
        adapt: artifact_sha256,
    },
    KindAdapter {
        kind: "ruby-gems",
        schema: Some("ruby-gems/1"),
        grammar: Grammar {
            required: &["schema", "installer"],
            optional: &["ruby_platform"],
            groups: &[("gem:", None)],
        },
        adapt: ruby_gems,
    },
];

/// `ruby-gems/1`: the installer is a `ruby<version>:<sha256>` fingerprint;
/// each gem contributes its `.gem` sha256.
fn ruby_gems(record: &Record, index: &MetaIndex) -> Result<ObjectDeps, String> {
    let installer = input(record, "installer")?;
    let (version, sha256) = installer
        .strip_prefix("ruby")
        .and_then(|rest| rest.split_once(':'))
        .ok_or_else(|| {
            format!("installer {installer:?} is not a ruby<version>:<sha256> reference")
        })?;
    let ruby = index.unique(
        "ruby",
        &format!("Ruby {version} built from artifact {sha256}"),
        |candidate| {
            candidate.identity.version == version
                && candidate
                    .identity
                    .inputs
                    .get("artifact_sha256")
                    .map(String::as_str)
                    == Some(sha256)
        },
    )?;
    let mut deps = ObjectDeps::new();
    add_object(&mut deps, &ruby, index, "installer")?;
    for (key, value) in &record.identity.inputs {
        if let Some(gem) = key.strip_prefix("gem:") {
            add_digest(&mut deps, Algo::Sha256, value, &format!("gem {gem}"))?;
        } else if key != "schema" && key != "installer" && key != "ruby_platform" {
            return Err(format!("unexpected identity input {key}"));
        }
    }
    Ok(deps)
}

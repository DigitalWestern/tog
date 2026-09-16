//! Object kinds the Ruby tailor produces. Each row has a migration grammar
//! for legacy records and a separate live grammar for current commits, plus
//! the `object-meta/2` dependency adapter. Every row is proven by the metadata
//! goldens in `kernel/objmeta.rs`.

use crate::kernel::objmeta::{
    add_digest, add_object, artifact_sha256, input, Algo, Grammar, KindAdapter, MetaIndex, Record,
};
use crate::kernel::store::ObjectDeps;
use crate::kernel::types::Identity;

pub static KINDS: &[KindAdapter] = &[
    KindAdapter {
        kind: "ruby",
        schema: Some("ruby-toolchain/1"),
        live_required: &["schema", "artifact_sha256", "platform"],
        live_optional: &[],
        legacy_only: &[],
        live_contract: None,
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
        live_required: &["schema", "installer", "ruby_platform"],
        live_optional: &["gem:"],
        legacy_only: &[],
        live_contract: Some(ruby_gems_contract),
        grammar: Grammar {
            required: &["schema", "installer"],
            optional: &["ruby_platform"],
            groups: &[("gem:", None)],
        },
        adapt: ruby_gems,
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
    Ok(())
}

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

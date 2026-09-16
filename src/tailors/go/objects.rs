//! Object kinds the Go tailor produces. Each row has a migration grammar
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
        kind: "go",
        schema: Some("go-toolchain/1"),
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
        kind: "go-modcache",
        schema: Some("go-modcache/1"),
        live_required: &["schema", "extractor"],
        live_optional: &["mod:", "modfile:", "info:"],
        legacy_only: &[],
        live_contract: Some(go_module_contract),
        grammar: Grammar {
            required: &["schema", "extractor"],
            optional: &[],
            // The producer writes the mod/modfile/info triplet for every
            // module; a record carrying only part of a triplet is truncated.
            groups: &[
                ("mod:", Some(&["modfile:", "info:"])),
                ("modfile:", Some(&["mod:", "info:"])),
                ("info:", Some(&["mod:", "modfile:"])),
            ],
        },
        adapt: go_modcache,
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

/// `go-modcache/1`: the extractor is a `go<version>:<sha256>` fingerprint, so
/// the Go toolchain object is found by matching the one `go` record with that
/// version and artifact digest. Each module contributes three cached files.
fn go_modcache(record: &Record, index: &MetaIndex) -> Result<ObjectDeps, String> {
    let extractor = input(record, "extractor")?;
    let (version, sha256) = extractor
        .strip_prefix("go")
        .and_then(|rest| rest.split_once(':'))
        .ok_or_else(|| {
            format!("extractor {extractor:?} is not a go<version>:<sha256> reference")
        })?;
    let go = index.unique(
        "go",
        &format!("Go {version} built from artifact {sha256}"),
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
    add_object(&mut deps, &go, index, "extractor")?;
    for (key, value) in &record.identity.inputs {
        if let Some(module) = key.strip_prefix("mod:") {
            // "<h1 hash>:<zip sha256>"; the h1 hash itself contains a colon.
            let (_, zip) = value
                .rsplit_once(':')
                .ok_or_else(|| format!("module {module} entry {value:?} has no zip digest"))?;
            add_digest(
                &mut deps,
                Algo::Sha256,
                zip,
                &format!("module {module} zip"),
            )?;
        } else if let Some(module) = key.strip_prefix("modfile:") {
            let (_, modfile) = value
                .rsplit_once(':')
                .ok_or_else(|| format!("module {module} go.mod entry {value:?} has no digest"))?;
            add_digest(
                &mut deps,
                Algo::Sha256,
                modfile,
                &format!("module {module} go.mod"),
            )?;
        } else if let Some(module) = key.strip_prefix("info:") {
            add_digest(
                &mut deps,
                Algo::Sha256,
                value,
                &format!("module {module} info"),
            )?;
        } else if key != "schema" && key != "extractor" {
            return Err(format!("unexpected identity input {key}"));
        }
    }
    Ok(deps)
}

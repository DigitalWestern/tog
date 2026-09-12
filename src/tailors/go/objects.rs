//! Object kinds the Go tailor produces, with the identity grammar each
//! producer writes and how a legacy record's dependencies are recovered from
//! it (the `object-meta/2` adapters; REFACTOR.md Stage 3 step 4). Every
//! row is proven by the metadata goldens in `kernel/objmeta.rs`.

use crate::kernel::objmeta::{
    add_digest, add_object, artifact_sha256, input, Algo, Grammar, KindAdapter, MetaIndex, Record,
};
use crate::kernel::store::ObjectDeps;

pub static KINDS: &[KindAdapter] = &[
    KindAdapter {
        kind: "go",
        schema: Some("go-toolchain/1"),
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

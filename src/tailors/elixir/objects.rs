//! Object kinds the Elixir tailor produces. Each row has a migration grammar
//! for legacy records and a separate live grammar for current commits, plus
//! the `object-meta/2` dependency adapter. Every row is proven by the metadata
//! goldens in `kernel/objmeta.rs`.

use crate::kernel::objmeta::{
    add_digest, add_object, input, platform_of, Algo, Grammar, KindAdapter, MetaIndex, Record,
};
use crate::kernel::store::ObjectDeps;
use crate::kernel::types::Identity;

pub static KINDS: &[KindAdapter] = &[
    KindAdapter {
        kind: "beam",
        schema: Some("beam-toolchain/1"),
        live_required: &[
            "schema",
            "otp_sha256",
            "elixir_sha256",
            "hex_sha512",
            "rebar3_sha512",
            "versions",
            "platform",
        ],
        live_optional: &["relocation_schema", "store_root"],
        legacy_only: &[],
        live_contract: Some(beam_contract),
        grammar: Grammar {
            required: &[
                "schema",
                "otp_sha256",
                "elixir_sha256",
                "hex_sha512",
                "rebar3_sha512",
            ],
            optional: &["platform", "versions", "relocation_schema", "store_root"],
            groups: &[],
        },
        adapt: beam_toolchain,
    },
    KindAdapter {
        kind: "hex-deps",
        schema: Some("hex-deps/1"),
        live_required: &["schema", "beam"],
        live_optional: &["dep:"],
        legacy_only: &[],
        live_contract: Some(hex_deps_contract),
        grammar: Grammar {
            required: &["schema", "beam"],
            optional: &[],
            groups: &[("dep:", None)],
        },
        adapt: hex_deps,
    },
];

fn beam_contract(identity: &Identity) -> Result<(), String> {
    let platform = platform_of(identity)?.ok_or_else(|| {
        "BEAM relocation relation: the producer must record a platform input".to_string()
    })?;
    let relocation = identity.inputs.contains_key("relocation_schema");
    let store_root = identity.inputs.contains_key("store_root");
    let linux = matches!(
        platform,
        crate::kernel::platform::Platform::X86_64UnknownLinuxGnu
    );
    if linux != relocation || linux != store_root {
        return Err(format!(
            "BEAM relocation relation: relocation_schema and store_root are both required on Linux and both forbidden on Darwin (platform {})",
            platform.triple()
        ));
    }
    Ok(())
}

fn hex_deps_contract(identity: &Identity) -> Result<(), String> {
    // Empty dependency plans are valid. The producer's version is the exact
    // count when dependencies exist, including zero for the empty shape.
    let deps = identity
        .inputs
        .keys()
        .filter(|key| key.starts_with("dep:"))
        .count();
    let version = identity.version.parse::<usize>().map_err(|_| {
        format!(
            "Hex dependency count/version relation: version {:?} is not a count for {deps} dep: inputs",
            identity.version
        )
    })?;
    if version != deps {
        return Err(format!(
            "Hex dependency count/version relation: version {version} does not match {deps} dep: inputs"
        ));
    }
    Ok(())
}
/// `beam-toolchain/1`: OTP and Elixir by sha256, Hex and rebar3 by sha512.
/// All four are direct identity inputs; the `versions` and relocation inputs
/// are not artifacts.
fn beam_toolchain(record: &Record, _index: &MetaIndex) -> Result<ObjectDeps, String> {
    let mut deps = ObjectDeps::new();
    for (key, algo) in [
        ("otp_sha256", Algo::Sha256),
        ("elixir_sha256", Algo::Sha256),
        ("hex_sha512", Algo::Sha512),
        ("rebar3_sha512", Algo::Sha512),
    ] {
        add_digest(&mut deps, algo, input(record, key)?, key)?;
    }
    Ok(deps)
}

/// `hex-deps/1`: the BEAM reference is a truncated digest over the toolchain
/// artifact hashes, so the object is found by recomputing that fingerprint
/// from each candidate `beam` record's *own* inputs — never from this
/// build's pins. Each dependency contributes its outer tarball sha256; the
/// inner checksum is a content hash of the unpacked tarball and was never a
/// cache key, so it is not an artifact dependency.
fn hex_deps(record: &Record, index: &MetaIndex) -> Result<ObjectDeps, String> {
    let fingerprint = input(record, "beam")?;
    let beam = index.unique(
        "beam",
        &format!("BEAM toolchain fingerprint {fingerprint}"),
        |candidate| beam_fingerprint_of(candidate).as_deref() == Some(fingerprint),
    )?;
    let mut deps = ObjectDeps::new();
    add_object(&mut deps, &beam, index, "beam")?;
    for (key, value) in &record.identity.inputs {
        if let Some(app) = key.strip_prefix("dep:") {
            // "<package>@<version>:<outer>:<inner>:<managers>"
            let mut fields = value.splitn(4, ':');
            let _package = fields.next();
            let outer = fields.next().ok_or_else(|| {
                format!("dependency {app} entry {value:?} has no outer tarball digest")
            })?;
            add_digest(
                &mut deps,
                Algo::Sha256,
                outer,
                &format!("hex package {app}"),
            )?;
        } else if key != "schema" && key != "beam" {
            return Err(format!("unexpected identity input {key}"));
        }
    }
    Ok(deps)
}

/// Recompute `elixir::beam_fingerprint` from a candidate BEAM record's own
/// identity inputs. Darwin and Linux use different formulas, and the Linux
/// one includes the relocation schema, so both are reproduced exactly.
pub fn beam_fingerprint_of(record: &Record) -> Option<String> {
    if record.identity.kind != "beam" || record.schema_input() != Some("beam-toolchain/1") {
        return None;
    }
    let inputs = &record.identity.inputs;
    let otp = inputs.get("otp_sha256")?;
    let elixir = inputs.get("elixir_sha256")?;
    let hex = inputs.get("hex_sha512")?;
    let rebar3 = inputs.get("rebar3_sha512")?;
    let joined = match inputs.get("relocation_schema") {
        Some(relocation) => format!("{otp}:{elixir}:{hex}:{rebar3}:{relocation}"),
        None => format!("{otp}:{elixir}:{hex}:{rebar3}"),
    };
    Some(crate::tailors::elixir::fingerprint_of_joined(&joined))
}

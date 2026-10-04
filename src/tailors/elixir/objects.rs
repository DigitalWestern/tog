//! Object kinds the Elixir tailor produces: one row per (kind, schema) pair,
//! naming the identity inputs its producer writes. Debug builds check every
//! commit against its row (`objmeta::check_identity_grammar`).

use crate::kernel::objmeta::{platform_of, ObjectKind};
use crate::kernel::types::Identity;

pub static KINDS: &[ObjectKind] = &[
    ObjectKind {
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
        live_contract: Some(beam_contract),
    },
    ObjectKind {
        kind: "hex-deps",
        schema: Some("hex-deps/1"),
        live_required: &["schema", "beam"],
        live_optional: &["dep:"],
        live_contract: Some(hex_deps_contract),
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

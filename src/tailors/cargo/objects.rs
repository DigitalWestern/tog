//! Object kinds the Cargo tailor produces: one row per (kind, schema) pair,
//! naming the identity inputs its producer writes. Debug builds check every
//! commit against its row (`objmeta::check_identity_grammar`).

use crate::kernel::objmeta::ObjectKind;
use crate::kernel::types::Identity;

pub static KINDS: &[ObjectKind] = &[
    ObjectKind {
        kind: "rust",
        schema: Some("rust-toolchain/1"),
        live_required: &[
            "schema",
            "cargo_sha256",
            "rust_std_sha256",
            "rustc_sha256",
            "platform",
        ],
        live_optional: &[],
        live_contract: None,
    },
    ObjectKind {
        kind: "rust",
        schema: Some("rust-toolchain/2"),
        live_required: &[
            "schema",
            "platform",
            "base",
            "channel_manifest_sha256",
            "extensions",
        ],
        live_optional: &["ext:"],
        live_contract: Some(rust_assembled_contract),
    },
    ObjectKind {
        kind: "rust",
        schema: Some("rust-path/1"),
        live_required: &["schema", "platform", "tree_sha256", "build"],
        live_optional: &[],
        live_contract: None,
    },
    ObjectKind {
        kind: "rust-component",
        schema: Some("rust-component/1"),
        live_required: &["schema", "platform", "target", "archive_sha256"],
        live_optional: &[],
        live_contract: None,
    },
    ObjectKind {
        kind: "rustfmt",
        schema: Some("rustfmt/1"),
        live_required: &["schema", "rust_object", "rustfmt_sha256", "platform"],
        live_optional: &[],
        live_contract: None,
    },
    ObjectKind {
        kind: "cargo-vendor",
        schema: Some("cargo-vendor/2"),
        live_required: &["schema", "crates"],
        live_optional: &["crate:"],
        live_contract: Some(cargo_vendor_v2_contract),
    },
];

/// The `cargo-vendor/1` producer used `identity.version == max(1,
/// crate_count)`. Under that schema a one-crate plan whose producer dropped
/// its `crate:` key was indistinguishable from the legitimate empty plan,
/// because `max(1, 0)` and `max(1, 1)` are the same number. `cargo-vendor/2`
/// closes it with a separate `crates` count; this row survives only for
/// records already in the store.
fn cargo_vendor_contract(identity: &Identity) -> Result<(), String> {
    let crates = identity
        .inputs
        .keys()
        .filter(|key| key.starts_with("crate:"))
        .count();
    let expected = crates.max(1);
    let version = identity.version.parse::<usize>().map_err(|_| {
        format!(
            "Cargo crate count/version relation: version {:?} is not a count for {} crate: inputs",
            identity.version, crates
        )
    })?;
    if version != expected {
        return Err(format!(
            "Cargo crate count/version relation: version {version} does not match {crates} crate: inputs"
        ));
    }
    Ok(())
}

/// `cargo-vendor/2` adds the `crates` input: the exact number of `crate:`
/// keys, written unconditionally, including the zero of an empty plan. A
/// dropped sole `crate:` key leaves `crates` at 1 with no crate entry, so
/// the empty plan and the drifted one-crate plan are different identities and
/// this contract names the difference.
fn cargo_vendor_v2_contract(identity: &Identity) -> Result<(), String> {
    // The `/1` relation runs first: where the version relation can already
    // name the drift, that message is the more specific one.
    cargo_vendor_contract(identity)?;
    let crates = identity
        .inputs
        .keys()
        .filter(|key| key.starts_with("crate:"))
        .count();
    let declared = identity
        .inputs
        .get("crates")
        .ok_or_else(|| "Cargo crate count relation: no crates input".to_string())?;
    let declared = declared
        .parse::<usize>()
        .map_err(|_| format!("Cargo crate count relation: crates {declared:?} is not a count"))?;
    if declared != crates {
        return Err(format!(
            "Cargo crate count relation: crates {declared} does not match {crates} crate: inputs"
        ));
    }
    Ok(())
}

/// `rust-toolchain/2`: an assembled toolchain names at least one extension
/// (an assembly of the base alone would be the base under a second id), and
/// its `extensions` count is the number of `ext:` keys, so a dropped key
/// cannot hash to a smaller request's id.
fn rust_assembled_contract(identity: &Identity) -> Result<(), String> {
    let keys = identity
        .inputs
        .keys()
        .filter(|key| key.starts_with("ext:"))
        .count();
    let declared = identity
        .inputs
        .get("extensions")
        .ok_or_else(|| "Rust extension count relation: no extensions input".to_string())?;
    let declared = declared.parse::<usize>().map_err(|_| {
        format!("Rust extension count relation: extensions {declared:?} is not a count")
    })?;
    if declared != keys {
        return Err(format!(
            "Rust extension count relation: extensions {declared} does not match {keys} ext: inputs"
        ));
    }
    if keys == 0 {
        return Err(
            "Rust extension count relation: an assembled toolchain names no extension".into(),
        );
    }
    Ok(())
}

//! Object kinds the Cargo tailor produces. Each row has a migration grammar
//! for legacy records and a separate live grammar for current commits, plus
//! the `object-meta/2` dependency adapter. Every row is proven by the metadata
//! goldens in `kernel/objmeta.rs`.

use crate::kernel::objmeta::{
    add_digest, add_object, input, Algo, Grammar, KindAdapter, MetaIndex, Record,
};
use crate::kernel::store::ObjectDeps;
use crate::kernel::types::Identity;

pub static KINDS: &[KindAdapter] = &[
    KindAdapter {
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
        legacy_only: &[],
        live_contract: None,
        grammar: Grammar {
            required: &["schema", "cargo_sha256", "rust_std_sha256", "rustc_sha256"],
            optional: &["platform"],
            groups: &[],
        },
        adapt: rust_toolchain,
    },
    KindAdapter {
        kind: "rustfmt",
        schema: Some("rustfmt/1"),
        live_required: &["schema", "rust_object", "rustfmt_sha256", "platform"],
        live_optional: &[],
        legacy_only: &[],
        live_contract: None,
        grammar: Grammar {
            required: &["schema", "rust_object", "rustfmt_sha256"],
            optional: &["platform"],
            groups: &[],
        },
        adapt: rustfmt,
    },
    KindAdapter {
        kind: "cargo-vendor",
        schema: Some("cargo-vendor/1"),
        live_required: &["schema"],
        live_optional: &["crate:"],
        legacy_only: &[],
        live_contract: Some(cargo_vendor_contract),
        grammar: Grammar {
            required: &["schema"],
            optional: &[],
            groups: &[("crate:", None)],
        },
        adapt: cargo_vendor,
    },
];

/// The `cargo-vendor/1` producer uses `identity.version == max(1,
/// crate_count)`. Under this schema, a one-crate plan whose producer dropped
/// its `crate:` key is indistinguishable from the legitimate empty plan.
/// Removing that ambiguity requires `cargo-vendor/2` with a separate count
/// input. That is a deliberate future identity change, not something this
/// guard can do.
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

/// `rust-toolchain/1`: the three components the producer merges, each named
/// by its own identity input. `cargo::rust_components` requires exactly
/// cargo + rust-std + rustc, which is what the identity commits to.
fn rust_toolchain(record: &Record, _index: &MetaIndex) -> Result<ObjectDeps, String> {
    let mut deps = ObjectDeps::new();
    for key in ["cargo_sha256", "rust_std_sha256", "rustc_sha256"] {
        add_digest(&mut deps, Algo::Sha256, input(record, key)?, key)?;
    }
    Ok(deps)
}

/// `rustfmt/1`: the paired Rust object is a direct identity input, and the
/// component tarball is its own sha256. `rustfmt/1` symlinks `lib` into the
/// Rust object, so the pairing is a real filesystem dependency.
fn rustfmt(record: &Record, index: &MetaIndex) -> Result<ObjectDeps, String> {
    let mut deps = ObjectDeps::new();
    add_object(
        &mut deps,
        input(record, "rust_object")?,
        index,
        "rust_object",
    )?;
    add_digest(
        &mut deps,
        Algo::Sha256,
        input(record, "rustfmt_sha256")?,
        "rustfmt_sha256",
    )?;
    Ok(deps)
}

/// `cargo-vendor/1`: one entry per crate. A registry crate contributes its
/// `.crate` sha256; a git crate contributes the realized `git-source` object.
///
/// The Rust toolchain is deliberately **not** a dependency of a vendor tree.
/// `cargo::realize_vendor_inner` runs only `tar`; no part of the toolchain is
/// a build input, and the vendor identity does not commit to one — so
/// recording it would make the same identity publishable with two different
/// dependency sets. See the deviation note in the ARCHITECTURE.md matrix.
fn cargo_vendor(record: &Record, index: &MetaIndex) -> Result<ObjectDeps, String> {
    let mut deps = ObjectDeps::new();
    for (key, value) in &record.identity.inputs {
        let Some(krate) = key.strip_prefix("crate:") else {
            if key == "schema" {
                continue;
            }
            return Err(format!("unexpected identity input {key}"));
        };
        match value.strip_prefix("git:") {
            Some(id) => add_object(&mut deps, id, index, &format!("crate {krate}"))?,
            None => add_digest(&mut deps, Algo::Sha256, value, &format!("crate {krate}"))?,
        }
    }
    Ok(deps)
}

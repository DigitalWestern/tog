//! Object kinds the Node tailor produces. Each row has a migration grammar
//! for legacy records and a separate live grammar for current commits, plus
//! the `object-meta/2` dependency adapter. Every row is proven by the metadata
//! goldens in `kernel/objmeta.rs`.

use crate::kernel::objmeta::{
    add_digest, add_object, artifact_sha256, input, parse_digest, Algo, Grammar, KindAdapter,
    MetaIndex, Record,
};
use crate::kernel::store::ObjectDeps;
use crate::kernel::types::Identity;

pub static KINDS: &[KindAdapter] = &[
    KindAdapter {
        kind: "nodejs",
        schema: None,
        superseded_by: None,
        live_required: &["artifact_sha256", "platform"],
        live_optional: &[],
        legacy_only: &[],
        live_contract: None,
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
        superseded_by: Some("node-env/4"),
        live_required: &["schema", "store_root", "nodejs", "workspaces"],
        live_optional: &["layout", "native_libs", "pkg:", "provisioned:", "artifact:"],
        legacy_only: &[],
        live_contract: Some(node_env_contract),
        grammar: Grammar {
            required: &["schema", "nodejs"],
            optional: &["store_root", "layout", "workspaces", "native_libs"],
            groups: &[("pkg:", None), ("provisioned:", None), ("artifact:", None)],
        },
        adapt: node_env_v3,
    },
    KindAdapter {
        kind: "node-env",
        schema: Some("node-env/4"),
        superseded_by: Some("node-env/5"),
        live_required: &[
            "schema",
            "store_root",
            "nodejs",
            "workspaces",
            "plan_digest",
            "native",
        ],
        live_optional: &["layout", "native_libs", "pkg:", "provisioned:", "artifact:"],
        legacy_only: &[],
        live_contract: Some(node_env_v4_contract),
        grammar: Grammar {
            required: &["schema", "nodejs", "plan_digest", "native"],
            optional: &["store_root", "layout", "workspaces", "native_libs"],
            groups: &[("pkg:", None), ("provisioned:", None), ("artifact:", None)],
        },
        adapt: node_env_v4,
    },
    KindAdapter {
        kind: "node-env",
        schema: Some("node-env/5"),
        superseded_by: None,
        live_required: &[
            "schema",
            "store_root",
            "nodejs",
            "workspaces",
            "plan_digest",
            "native",
            "gyp_python",
        ],
        live_optional: &["layout", "native_libs", "pkg:", "provisioned:", "artifact:"],
        legacy_only: &[],
        live_contract: Some(node_env_v5_contract),
        grammar: Grammar {
            required: &["schema", "nodejs", "plan_digest", "native", "gyp_python"],
            optional: &["store_root", "layout", "workspaces", "native_libs"],
            groups: &[("pkg:", None), ("provisioned:", None), ("artifact:", None)],
        },
        adapt: node_env_v5,
    },
];

/// `node-env/3` could not detect three identity drifts. Dropping one package
/// from a multi-package plan left another `pkg:` key, so the presence checks
/// passed. Dropping an `artifact:` or Linux `native_libs` key also passed,
/// because those checks were conditional on the key being present.
/// `node-env/4` closes all three; this row survives only for records already
/// in the store. A dropped `provisioned:` key was always detected: the
/// `pkg:` value names the package, and the producer's own provisioning
/// decision says which packages must carry one.
fn node_env_contract(identity: &Identity) -> Result<(), String> {
    let inputs = &identity.inputs;
    // A lockfile with no installable packages is legitimate. In that shape
    // the producer writes `layout` and no pkg: key; artifact: is an
    // independently optional input.
    let has_packages = inputs.keys().any(|key| key.starts_with("pkg:"));
    let has_layout = inputs.contains_key("layout");
    for (key, value) in inputs.iter().filter(|(key, _)| key.starts_with("pkg:")) {
        let path = &key["pkg:".len()..];
        let (name, version) = package_name_and_version(value).ok_or_else(|| {
            format!(
                "Node pkg/provisioned relation: {key} value {value:?} has no name@version field"
            )
        })?;
        let provisioned_key = format!("provisioned:{path}");
        if super::realize::provisioned_version(name, version).is_some()
            && !inputs.contains_key(&provisioned_key)
        {
            return Err(format!(
                "Node pkg/provisioned relation: {key} names provisioned package {name}@{version} and requires {provisioned_key}"
            ));
        }
    }
    for key in inputs.keys().filter(|key| key.starts_with("provisioned:")) {
        let suffix = &key["provisioned:".len()..];
        let package_key = format!("pkg:{suffix}");
        if !inputs.contains_key(&package_key) {
            return Err(format!(
                "Node provisioned/pkg relation: {key} requires {package_key}"
            ));
        }
    }
    if inputs.contains_key("native_libs") && !has_packages {
        return Err("Node native_libs/pkg relation: native_libs requires a pkg: input".into());
    }
    if inputs.contains_key("native_libs")
        && super::platform_of_node_object(
            inputs
                .get("nodejs")
                .ok_or_else(|| "Node native platform relation: no nodejs input".to_string())?,
        ) != Some(crate::kernel::platform::Platform::X86_64UnknownLinuxGnu)
    {
        return Err(
            "Node native platform relation: native_libs is only produced for Linux Node objects"
                .into(),
        );
    }
    if has_layout == has_packages {
        return Err(
            "Node layout/package relation: layout is present exactly when no pkg: input exists"
                .into(),
        );
    }
    Ok(())
}

/// `node-env/4` adds two unconditional inputs to the `/3` shape: a
/// `plan_digest` over every `pkg:` and `artifact:` entry, and a `native`
/// decision the producer spells out whether or not it mounts the library
/// set. A dropped package or declared artifact now leaves a digest no plan
/// produces, and a dropped `native_libs` key leaves `native` claiming a
/// mount that is not there. Both are recomputed here from the producer's own
/// functions.
fn node_env_v4_contract(identity: &Identity) -> Result<(), String> {
    // The `/3` relations run first: when one of them can name the exact
    // pairing that broke, that is a better diagnostic than "the digest moved".
    node_env_contract(identity)?;
    let inputs = &identity.inputs;
    let declared = inputs
        .get("plan_digest")
        .ok_or_else(|| "Node plan digest: no plan_digest input".to_string())?;
    let recomputed = super::realize::plan_digest_of_inputs(inputs);
    if *declared != recomputed {
        return Err(format!(
            "Node plan digest: plan_digest {declared} does not match the {recomputed} this \
             package and artifact set hashes to"
        ));
    }
    let native = inputs
        .get("native")
        .ok_or_else(|| "Node native decision: no native input".to_string())?;
    let expected = match inputs.contains_key("native_libs") {
        true => super::realize::NATIVE_LIBS_MOUNTED,
        false => super::realize::NATIVE_NONE,
    };
    if native != expected {
        return Err(format!(
            "Node native decision: native {native:?} does not match the {expected:?} this \
             identity's native_libs input implies"
        ));
    }
    Ok(())
}

/// `node-env/5` adds one unconditional input to the `/4` shape: `gyp_python`,
/// the object id of the CPython node-gyp runs on. Under `/4` that interpreter
/// was the shipped pin and named nowhere, so a pin change could rebuild a
/// native addon under an unchanged id; now it is the project's locked Python
/// (or the shipped default) and the id commits to it.
fn node_env_v5_contract(identity: &Identity) -> Result<(), String> {
    node_env_v4_contract(identity)?;
    let gyp_python = identity
        .inputs
        .get("gyp_python")
        .ok_or_else(|| "Node gyp python: no gyp_python input".to_string())?;
    if !is_cpython_object_id(gyp_python) {
        return Err(format!(
            "Node gyp python: gyp_python {gyp_python:?} is not a CPython object id"
        ));
    }
    Ok(())
}

/// `<40 hex>-cpython-<version>`: the spelling every `cpython` object id has.
fn is_cpython_object_id(value: &str) -> bool {
    value
        .split_once("-cpython-")
        .is_some_and(|(hash, version)| {
            hash.len() == 40
                && hash
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
                && !version.is_empty()
        })
}

/// The `<name>@<version>` field of a `pkg:` value. The producer writes
/// `<algo>:<hex>:<name>@<version>:patch[..]:bin[..]` for a registry package
/// and `git:<object id>:<name>@<version>:...` for a git package; the name may
/// be scoped (`@scope/pkg`) but never contains a colon.
fn package_name_and_version(value: &str) -> Option<(&str, &str)> {
    let name_version = value.splitn(4, ':').nth(2)?;
    name_version.rsplit_once('@')
}

/// `node-env/3`: Node and the native library set are direct object ids; a
/// registry package contributes the SRI digest embedded in its `pkg:` entry
/// (in the algorithm npm published, which may be sha1, sha256 or sha512); a
/// git package contributes its realized `git-source` object.
fn node_env_v3(record: &Record, index: &MetaIndex) -> Result<ObjectDeps, String> {
    node_env_inner(
        record,
        index,
        &[
            "schema",
            "store_root",
            "nodejs",
            "layout",
            "workspaces",
            "native_libs",
        ],
    )
}

/// `node-env/4`: the same byte sources. `plan_digest` and `native` are drift
/// guards over entries already named here, so neither adds a dependency.
///
/// Every object of this schema was committed with explicit evidence,
/// so legacy migration cannot reach it in practice; the metadata
/// goldens in `kernel/objmeta.rs` are what exercise this adapter.
fn node_env_v4(record: &Record, index: &MetaIndex) -> Result<ObjectDeps, String> {
    node_env_inner(
        record,
        index,
        &[
            "schema",
            "store_root",
            "nodejs",
            "layout",
            "workspaces",
            "native_libs",
            "plan_digest",
            "native",
        ],
    )
}

/// `node-env/5`: the `/4` byte sources. `gyp_python` names the interpreter
/// install scripts ran on, which is realized only when a package runs one
/// and never executed by the finished tree, so it is an identity input and
/// not a dependency: a pure-JavaScript environment must not pull in a
/// CPython just to be retained.
fn node_env_v5(record: &Record, index: &MetaIndex) -> Result<ObjectDeps, String> {
    node_env_inner(
        record,
        index,
        &[
            "schema",
            "store_root",
            "nodejs",
            "layout",
            "workspaces",
            "native_libs",
            "plan_digest",
            "native",
            "gyp_python",
        ],
    )
}

/// `provisioned:` and `artifact:` digests are claimed unconditionally, which
/// is a deliberate superset of what the producer now records (only the ones
/// an install script was given; see `run_install_scripts`). Whether a script
/// consumed one is not recoverable from the identity, and dropping a digest
/// whose file is cached would narrow what the legacy reader retained, so the
/// containment guard would refuse the upgrade anyway. Naming an absent
/// digest retains nothing, so the superset costs nothing.
fn node_env_inner(
    record: &Record,
    index: &MetaIndex,
    scalars: &[&str],
) -> Result<ObjectDeps, String> {
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
        } else if !scalars.contains(&key.as_str()) {
            return Err(format!("unexpected identity input {key}"));
        }
    }
    Ok(deps)
}

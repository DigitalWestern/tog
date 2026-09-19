//! CycloneDX 1.5 component builders (kernel layer): the JSON shapes every
//! tailor's `sbom_components` emits and the purl encoding they share.
//! `commands/sbom.rs` assembles the document; nothing here knows an ecosystem.

use serde_json::{json, Value};
use std::io;
use std::path::Path;

pub fn err(msg: impl Into<String>) -> io::Error {
    io::Error::other(msg.into())
}

/// Minimal percent-encoding for purl components: keep unreserved chars,
/// encode the rest (notably '@', '%', '/', spaces).
pub fn purl_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'-' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Go module paths keep their '/' separators; each segment is encoded.
pub fn purl_encode_path(s: &str) -> String {
    s.split('/').map(purl_encode).collect::<Vec<_>>().join("/")
}

pub fn component(name: &str, version: &str, purl: String, ecosystem: &str) -> Value {
    json!({
        "type": "library",
        "name": name,
        "version": version,
        "purl": purl,
        "properties": [{"name": "tog:ecosystem", "value": ecosystem}],
    })
}

pub fn push_hash(c: &mut Value, alg: &str, hex: &str) {
    c["hashes"] = json!([{"alg": alg, "content": hex}]);
}

pub fn push_property(c: &mut Value, name: &str, value: &str) {
    c["properties"]
        .as_array_mut()
        .unwrap()
        .push(json!({"name": name, "value": value}));
}

/// A store reference is either an object_ref {path,id} or a bare path string
/// (python/node closures); the store id is the last path component. A
/// malformed or missing reference is an error, never a silent omission.
pub fn toolchain_component(
    body: &Value,
    key: &str,
    name: &str,
    version: &str,
) -> io::Result<Value> {
    let bad = || err(format!("closure: missing or malformed '{key}'"));
    let v = body.get(key).ok_or_else(bad)?;
    let id = match v {
        Value::String(p) => Path::new(p)
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(bad)?
            .to_string(),
        _ => v
            .get("id")
            .and_then(|i| i.as_str())
            .ok_or_else(bad)?
            .to_string(),
    };
    if id.is_empty() {
        return Err(bad());
    }
    Ok(json!({
        "type": "application",
        "name": name,
        "version": version,
        "properties": [{"name": "tog:store-id", "value": id}],
    }))
}

/// Every extraction fails closed: an SBOM with silently absent packages
/// or blank versions would be a lie about the inventory.
pub fn list(eco: &str, plan: &Value, key: &str) -> io::Result<Vec<Value>> {
    plan.get(key)
        .and_then(|v| v.as_array())
        .cloned()
        .ok_or_else(|| err(format!("{eco} closure: missing or non-array '{key}'")))
}

pub fn required(eco: &str, v: &Value, k: &str) -> io::Result<String> {
    v.get(k)
        .and_then(|x| x.as_str())
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| err(format!("{eco} closure: package missing '{k}'")))
}

pub fn version_of(eco: &str, holder: &Value, k: &str) -> io::Result<String> {
    holder
        .get(k)
        .and_then(|x| x.as_str())
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| err(format!("{eco} closure: missing '{k}'")))
}

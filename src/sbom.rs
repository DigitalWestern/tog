//! `blanket sbom` — CycloneDX 1.5 JSON from the closure envelopes.
//!
//! Pure format translation: reads every .blanket/closures/<eco>.json the
//! project has and emits one SBOM document. No network, no new inputs —
//! the closures already carry names, versions, and pinned hashes.

use serde_json::{json, Value};
use std::fs;
use std::io;
use std::path::Path;

fn err(msg: impl Into<String>) -> io::Error {
    io::Error::other(msg.into())
}

/// Minimal percent-encoding for purl components: keep unreserved chars,
/// encode the rest (notably '@', '%', '/', spaces).
fn purl_encode(s: &str) -> String {
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
fn purl_encode_path(s: &str) -> String {
    s.split('/').map(purl_encode).collect::<Vec<_>>().join("/")
}

/// urn:uuid v4 from /dev/urandom.
fn serial_number() -> io::Result<String> {
    use std::io::Read;
    let mut bytes = [0u8; 16];
    fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let h: Vec<String> = bytes.iter().map(|b| format!("{b:02x}")).collect();
    Ok(format!(
        "urn:uuid:{}{}{}{}-{}{}-{}{}-{}{}-{}{}{}{}{}{}",
        h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7], h[8], h[9], h[10], h[11], h[12], h[13],
        h[14], h[15]
    ))
}

fn component(name: &str, version: &str, purl: String, ecosystem: &str) -> Value {
    json!({
        "type": "library",
        "name": name,
        "version": version,
        "purl": purl,
        "properties": [{"name": "blanket:ecosystem", "value": ecosystem}],
    })
}

fn push_hash(c: &mut Value, alg: &str, hex: &str) {
    c["hashes"] = json!([{"alg": alg, "content": hex}]);
}

fn push_property(c: &mut Value, name: &str, value: &str) {
    c["properties"]
        .as_array_mut()
        .unwrap()
        .push(json!({"name": name, "value": value}));
}

/// A store reference is either an object_ref {path,id} or a bare path string
/// (python/node closures); the store id is the last path component. A
/// malformed or missing reference is an error, never a silent omission.
fn toolchain_component(body: &Value, key: &str, name: &str, version: &str) -> io::Result<Value> {
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
        "properties": [{"name": "blanket:store-id", "value": id}],
    }))
}

/// npm lockfile path ("node_modules/a/node_modules/@s/b") -> package name.
fn npm_name_from_path(path: &str) -> &str {
    match path.rfind("node_modules/") {
        Some(i) => &path[i + "node_modules/".len()..],
        None => path,
    }
}

fn eco_components(eco: &str, body: &Value, out: &mut Vec<Value>) -> io::Result<()> {
    let plan = body.get("plan").unwrap_or(body);
    // Every extraction fails closed: an SBOM with silently absent packages
    // or blank versions would be a lie about the inventory.
    let list = |key: &str| -> io::Result<Vec<Value>> {
        plan.get(key)
            .and_then(|v| v.as_array())
            .cloned()
            .ok_or_else(|| err(format!("{eco} closure: missing or non-array '{key}'")))
    };
    let required = |v: &Value, k: &str| -> io::Result<String> {
        v.get(k)
            .and_then(|x| x.as_str())
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .ok_or_else(|| err(format!("{eco} closure: package missing '{k}'")))
    };
    let version_of = |holder: &Value, k: &str| -> io::Result<String> {
        holder
            .get(k)
            .and_then(|x| x.as_str())
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .ok_or_else(|| err(format!("{eco} closure: missing '{k}'")))
    };
    match eco {
        "python" => {
            for p in list("packages")? {
                let (name, ver) = (required(&p, "name")?, required(&p, "version")?);
                let norm = name.to_ascii_lowercase().replace('_', "-");
                let mut c = component(
                    &name,
                    &ver,
                    format!("pkg:pypi/{}@{}", purl_encode(&norm), purl_encode(&ver)),
                    eco,
                );
                push_hash(&mut c, "SHA-256", &required(&p, "sha256")?);
                out.push(c);
            }
            out.push(toolchain_component(
                body,
                "env_object",
                "python-env",
                &version_of(plan, "python_version")?,
            )?);
        }
        "node" => {
            for p in list("packages")? {
                let path = required(&p, "path")?;
                let name = npm_name_from_path(&path).to_string();
                let ver = required(&p, "version")?;
                // Scoped names: '@scope/x' -> '%40scope/x' per the purl spec.
                let purl_name = match name.strip_prefix('@') {
                    Some(rest) => match rest.split_once('/') {
                        Some((scope, n)) => {
                            format!("%40{}/{}", purl_encode(scope), purl_encode(n))
                        }
                        None => purl_encode(&name),
                    },
                    None => purl_encode(&name),
                };
                let mut c = component(
                    &name,
                    &ver,
                    format!("pkg:npm/{}@{}", purl_name, purl_encode(&ver)),
                    eco,
                );
                // integrity is an SRI string (base64), not a hex digest;
                // recorded as a property rather than a malformed hash entry.
                push_property(&mut c, "blanket:integrity", &required(&p, "integrity")?);
                out.push(c);
            }
            out.push(toolchain_component(
                body,
                "env_object",
                "node-env",
                &version_of(body, "node_version")?,
            )?);
        }
        "cargo" => {
            for p in list("crates")? {
                let (name, ver) = (required(&p, "name")?, required(&p, "version")?);
                let mut c = component(
                    &name,
                    &ver,
                    format!("pkg:cargo/{}@{}", purl_encode(&name), purl_encode(&ver)),
                    eco,
                );
                push_hash(&mut c, "SHA-256", &required(&p, "sha256")?);
                out.push(c);
            }
            out.push(toolchain_component(
                body,
                "rust_object",
                "rust",
                &version_of(plan, "rust_version")?,
            )?);
        }
        "go" => {
            for p in list("modules")? {
                let (path, ver) = (required(&p, "path")?, required(&p, "version")?);
                let mut c = component(
                    &path,
                    &ver,
                    format!("pkg:golang/{}@{}", purl_encode_path(&path), purl_encode(&ver)),
                    eco,
                );
                push_hash(&mut c, "SHA-256", &required(&p, "zip_sha256")?);
                push_property(&mut c, "blanket:go:h1", &required(&p, "h1")?);
                out.push(c);
            }
            out.push(toolchain_component(
                body,
                "go_object",
                "go",
                &version_of(plan, "go_version")?,
            )?);
        }
        "ruby" => {
            for p in list("gems")? {
                let (name, ver, platform) = (
                    required(&p, "name")?,
                    required(&p, "version")?,
                    required(&p, "platform")?,
                );
                let qualifier = if platform.is_empty() || platform == "ruby" {
                    String::new()
                } else {
                    format!("?platform={}", purl_encode(&platform))
                };
                let mut c = component(
                    &name,
                    &ver,
                    format!("pkg:gem/{}@{}{}", purl_encode(&name), purl_encode(&ver), qualifier),
                    eco,
                );
                push_hash(&mut c, "SHA-256", &required(&p, "sha256")?);
                out.push(c);
            }
            out.push(toolchain_component(
                body,
                "ruby_object",
                "ruby",
                &version_of(plan, "ruby_version")?,
            )?);
        }
        "elixir" => {
            for p in list("deps")? {
                let (name, ver) = (required(&p, "package")?, required(&p, "version")?);
                let mut c = component(
                    &name,
                    &ver,
                    format!("pkg:hex/{}@{}", purl_encode(&name.to_ascii_lowercase()), purl_encode(&ver)),
                    eco,
                );
                push_hash(&mut c, "SHA-256", &required(&p, "outer_sha256")?);
                push_property(
                    &mut c,
                    "blanket:hex:inner-checksum",
                    &required(&p, "inner_sha256")?,
                );
                out.push(c);
            }
            let beam_version = format!(
                "otp-{}-elixir-{}",
                version_of(plan, "otp_version")?,
                version_of(plan, "elixir_version")?,
            );
            out.push(toolchain_component(body, "beam_object", "beam", &beam_version)?);
        }
        "dotnet" => {
            for p in list("packages")? {
                let (id, ver) = (required(&p, "id")?, required(&p, "version")?);
                let mut c = component(
                    &id,
                    &ver,
                    format!("pkg:nuget/{}@{}", purl_encode(&id), purl_encode(&ver)),
                    eco,
                );
                // contentHash is NuGet's semantic (signature-stripped)
                // sha512, base64 — not a raw file digest.
                push_property(
                    &mut c,
                    "blanket:nuget:contentHash",
                    &required(&p, "content_hash")?,
                );
                out.push(c);
            }
            out.push(toolchain_component(
                body,
                "sdk_object",
                "dotnet-sdk",
                &version_of(plan, "sdk_version")?,
            )?);
        }
        other => {
            return Err(err(format!("unknown closure ecosystem '{other}'")));
        }
    }
    Ok(())
}

/// Build the CycloneDX document for every closure in the project.
pub fn generate(project_dir: &Path) -> io::Result<Value> {
    let dir = project_dir.join(".blanket/closures");
    let mut entries: Vec<String> = match fs::read_dir(&dir) {
        Ok(rd) => rd
            .filter_map(|e| e.ok())
            .filter_map(|e| e.file_name().to_str().map(String::from))
            .filter(|n| n.ends_with(".json") && !n.starts_with('.'))
            .map(|n| n.trim_end_matches(".json").to_string())
            .collect(),
        Err(_) => Vec::new(),
    };
    entries.sort();
    if entries.is_empty() {
        return Err(err("no closures found; run `blanket sync` first"));
    }
    let mut components = Vec::new();
    for eco in &entries {
        let body = crate::project::read_closure(project_dir, eco)?;
        eco_components(eco, &body, &mut components)?;
    }
    Ok(json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": serial_number()?,
        "version": 1,
        "metadata": {
            "tools": [{
                "vendor": "blanket",
                "name": "blanket",
                "version": env!("CARGO_PKG_VERSION"),
            }],
        },
        "components": components,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sbom_from_synthetic_closures() {
        let dir = std::env::temp_dir().join(format!(
            "blanket-sbom-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(dir.join(".blanket/closures")).unwrap();
        let write = |eco: &str, body: Value| {
            let envelope = json!({
                "schema": "closure/1",
                "ecosystem": eco,
                "projected_at": 0,
                "body": body,
            });
            fs::write(
                dir.join(format!(".blanket/closures/{eco}.json")),
                serde_json::to_vec(&envelope).unwrap(),
            )
            .unwrap();
        };
        write(
            "python",
            json!({
                "env_object": "/store/objects/abc123",
                "plan": {
                    "python_version": "3.13.1",
                    "packages": [
                        {"name": "Flask_Login", "version": "0.6.3", "sha256": "aa".repeat(32)},
                    ],
                },
            }),
        );
        write(
            "node",
            json!({
                "env_object": "/store/objects/def456",
                "node_version": "24.20.0",
                "packages": [
                    {"path": "node_modules/@types/node", "version": "22.0.0",
                     "integrity": "sha512-xyz"},
                    {"path": "node_modules/a/node_modules/b", "version": "1.0.0",
                     "integrity": "sha512-abc"},
                ],
            }),
        );
        let doc = generate(&dir).unwrap();
        assert_eq!(doc["bomFormat"], "CycloneDX");
        assert_eq!(doc["specVersion"], "1.5");
        assert!(doc["serialNumber"].as_str().unwrap().starts_with("urn:uuid:"));
        let comps = doc["components"].as_array().unwrap();
        // 1 pypi env + 2 npm + 2 dependency environments
        assert_eq!(comps.len(), 5);
        let purls: Vec<&str> =
            comps.iter().filter_map(|c| c["purl"].as_str()).collect();
        assert!(purls.contains(&"pkg:pypi/flask-login@0.6.3"));
        assert!(purls.contains(&"pkg:npm/%40types/node@22.0.0"));
        assert!(purls.contains(&"pkg:npm/b@1.0.0"));
        let ids: Vec<&str> = comps
            .iter()
            .filter(|c| c["type"] == "application")
            .flat_map(|c| c["properties"].as_array().unwrap())
            .filter(|p| p["name"] == "blanket:store-id")
            .filter_map(|p| p["value"].as_str())
            .collect();
        // Closures are processed in ecosystem name order: node, then python.
        assert_eq!(ids, ["def456", "abc123"]);
        let env_names: Vec<&str> = comps
            .iter()
            .filter(|c| c["type"] == "application")
            .filter_map(|c| c["name"].as_str())
            .collect();
        assert_eq!(env_names, ["node-env", "python-env"]);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn sbom_requires_package_fields() {
        let body = json!({
            "plan": {
                "packages": [{"name": "Flask", "version": "3.0.0"}],
            },
        });
        let mut components = Vec::new();
        let error = eco_components("python", &body, &mut components)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("python closure: package missing 'sha256'"),
            "{error}"
        );
    }

    #[test]
    fn no_closures_is_a_loud_error() {
        let dir = std::env::temp_dir().join(format!(
            "blanket-sbom-empty-{}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).unwrap();
        assert!(generate(&dir).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }
}

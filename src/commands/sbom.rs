//! `tog sbom` — CycloneDX 1.5 JSON from the closure envelopes.
//!
//! Pure format translation: reads every .tog/closures/<eco>.json the
//! project has and emits one SBOM document. No network, no new inputs —
//! the closures already carry names, versions, and pinned hashes.

use crate::commands::shared::project_dir;
use crate::kernel::cyclonedx::err;
use crate::kernel::ui;
use crate::tailors;
use serde_json::{json, Value};
use std::io;
use std::path::Path;

/// urn:uuid v4 from the shared operating-system randomness helper.
fn serial_number() -> io::Result<String> {
    let bytes = crate::kernel::fsroot::urandom_bytes(16)?;
    let mut bytes: [u8; 16] = bytes
        .try_into()
        .map_err(|_| io::Error::other("system randomness returned the wrong length"))?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let h: Vec<String> = bytes.iter().map(|b| format!("{b:02x}")).collect();
    Ok(format!(
        "urn:uuid:{}{}{}{}-{}{}-{}{}-{}{}-{}{}{}{}{}{}",
        h[0],
        h[1],
        h[2],
        h[3],
        h[4],
        h[5],
        h[6],
        h[7],
        h[8],
        h[9],
        h[10],
        h[11],
        h[12],
        h[13],
        h[14],
        h[15]
    ))
}

fn eco_components(eco: &str, body: &Value, out: &mut Vec<Value>) -> io::Result<()> {
    match tailors::for_closure(eco) {
        Some(tailor) => tailor.sbom_components(eco, body, out),
        None => Err(err(format!("unknown closure ecosystem '{eco}'"))),
    }
}

/// Build the CycloneDX document for every closure in the project. The
/// closures are read as committed, whichever platform projected them: the
/// SBOM describes what the record says, so a Linux runner can describe a
/// closure synced on a Mac. Nothing here opens the store.
pub fn generate(project_dir: &Path) -> io::Result<Value> {
    let mut closures = crate::commands::inspect::closures(project_dir)?;
    closures.sort_by(|a, b| a.ecosystem.cmp(&b.ecosystem));
    if closures.is_empty() {
        return Err(err("no closures found; run `tog` first"));
    }
    let mut components = Vec::new();
    let mut exception_properties = Vec::new();
    for closure in &closures {
        let eco = &closure.ecosystem;
        let stem = closure.path.file_stem().and_then(|stem| stem.to_str());
        if closure.envelope["schema"] != "closure/1"
            || closure.envelope["ecosystem"].as_str() != stem
        {
            return Err(err(format!(
                "{}: unknown closure schema/ecosystem; re-run `tog`",
                closure.path.display()
            )));
        }
        let body = &closure.body;
        if let Some(exceptions) = body.get("exceptions").and_then(Value::as_array) {
            for exception in exceptions {
                let kind = exception
                    .get("kind")
                    .and_then(Value::as_str)
                    .ok_or_else(|| err(format!("{eco} closure: exception missing 'kind'")))?;
                let subject = exception
                    .get("subject")
                    .and_then(Value::as_str)
                    .ok_or_else(|| err(format!("{eco} closure: exception missing 'subject'")))?;
                let detail = exception
                    .get("detail")
                    .and_then(Value::as_str)
                    .ok_or_else(|| err(format!("{eco} closure: exception missing 'detail'")))?;
                exception_properties.push(json!({
                    "name": format!("tog:exception:{kind}"),
                    "value": format!("{subject}: {detail}"),
                }));
            }
        }
        eco_components(eco, body, &mut components)?;
    }
    Ok(json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": serial_number()?,
        "version": 1,
        "metadata": {
            "tools": [{
                "vendor": "tog",
                "name": "tog",
                "version": env!("CARGO_PKG_VERSION"),
            }],
            "properties": exception_properties,
        },
        "components": components,
    }))
}

pub fn run(output: Option<&Path>) -> io::Result<()> {
    let doc = generate(&project_dir())?;
    let text = serde_json::to_string_pretty(&doc)?;
    match output {
        Some(path) => {
            std::fs::write(path, text + "\n")?;
            ui::note(&format!("SBOM written to {}", path.display()));
        }
        None => println!("{text}"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::testutil::TempDir;
    use std::fs;

    #[test]
    fn sbom_from_synthetic_closures() {
        let scratch = TempDir::named("sbom-test");
        let dir = scratch.0.clone();
        fs::create_dir_all(dir.join(".tog/closures")).unwrap();
        let write = |eco: &str, body: Value| {
            let envelope = json!({
                "schema": "closure/1",
                "ecosystem": eco,
                "projected_at": 0,
                "body": body,
            });
            fs::write(
                dir.join(format!(".tog/closures/{eco}.json")),
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
                "exceptions": [{
                    "kind": "requirement-skipped",
                    "subject": ".",
                    "detail": "project-local requirement",
                }],
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
                "exceptions": [{
                    "kind": "install-script-failed",
                    "subject": "node_modules/a",
                    "detail": "postinstall: network-denied",
                }],
            }),
        );
        // The record an older `tog fmt` left: not a closure any more, so it
        // is skipped rather than failing the whole document.
        write(
            "rustfmt",
            json!({
                "rust_object": {"path": "/store/objects/rust789", "id": "rust789"},
                "rustfmt_object": {"path": "/store/objects/fmt012", "id": "fmt012"},
                "rust_version": "1.96.1",
                "workspace_root": "/w",
            }),
        );
        let doc = generate(&dir).unwrap();
        assert_eq!(doc["bomFormat"], "CycloneDX");
        assert_eq!(doc["specVersion"], "1.5");
        assert!(doc["serialNumber"]
            .as_str()
            .unwrap()
            .starts_with("urn:uuid:"));
        let comps = doc["components"].as_array().unwrap();
        // 1 pypi + 2 npm + 2 dependency environments
        assert_eq!(comps.len(), 5);
        let purls: Vec<&str> = comps.iter().filter_map(|c| c["purl"].as_str()).collect();
        assert!(purls.contains(&"pkg:pypi/flask-login@0.6.3"));
        assert!(purls.contains(&"pkg:npm/%40types/node@22.0.0"));
        assert!(purls.contains(&"pkg:npm/b@1.0.0"));
        let ids: Vec<&str> = comps
            .iter()
            .filter(|c| c["type"] == "application")
            .flat_map(|c| c["properties"].as_array().unwrap())
            .filter(|p| p["name"] == "tog:store-id")
            .filter_map(|p| p["value"].as_str())
            .collect();
        // Closures are processed in name order: node, then python.
        assert_eq!(ids, ["def456", "abc123"]);
        let env_names: Vec<&str> = comps
            .iter()
            .filter(|c| c["type"] == "application")
            .filter_map(|c| c["name"].as_str())
            .collect();
        assert_eq!(env_names, ["node-env", "python-env"]);
        let properties = doc["metadata"]["properties"].as_array().unwrap();
        assert!(properties.iter().any(|p| {
            p["name"] == "tog:exception:requirement-skipped"
                && p["value"] == ".: project-local requirement"
        }));
        assert!(properties.iter().any(|p| {
            p["name"] == "tog:exception:install-script-failed"
                && p["value"] == "node_modules/a: postinstall: network-denied"
        }));
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
        let dir = TempDir::named("sbom-empty");
        let error = generate(&dir.0).unwrap_err();
        assert!(error.to_string().contains("no closures found"), "{error}");
    }
}

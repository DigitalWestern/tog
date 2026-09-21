//! Committed toolchain lock: which exact toolchain each ecosystem uses.
//!
//! The file is `tog-toolchain.toml` next to the manifests, outside the
//! ignored `.tog/` directory. It records one bundle per ecosystem plus the
//! whole consulted input list, including sources that held no request, so a
//! new higher-precedence file flips a row from absent to present instead of
//! changing nothing the lock knows about.
//!
//! This module owns parsing, strict validation, and canonical writing. The
//! lock is dormant: nothing here writes or requires it. Creation and
//! enforcement arrive with activation; this PR only reads inputs and proves
//! the file round-trips byte-identically.

use crate::kernel::fsroot::ProjectRoot;
use std::collections::BTreeMap;
use std::io;
use std::path::Path;

/// Project-relative path of the lock file.
pub const LOCK_PATH: &str = "tog-toolchain.toml";

/// Supported lock schema version. A schema that adds a hashed field mints a
/// new version; old files keep the id their own bytes produced.
pub const SCHEMA_VERSION: u64 = 1;

fn invalid(what: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, what.into())
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct ComponentLock {
    version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    embedded_in: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct InputToml {
    path: String,
    field: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    absent: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sha256: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct ArtifactLock {
    provider: String,
    build: String,
    recipe: String,
    url: String,
    digest: String,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct PlatformLock {
    artifacts: BTreeMap<String, ArtifactLock>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct EcoLock {
    runtime: String,
    release: String,
    bundle_id: String,
    primary: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    revision: Option<u64>,
    components: Vec<String>,
    #[serde(default)]
    component: BTreeMap<String, ComponentLock>,
    #[serde(default)]
    inputs: Vec<InputToml>,
    #[serde(default)]
    platforms: BTreeMap<String, PlatformLock>,
}

/// The parsed lock file. Field order in the writer below is the canonical
/// order; the map order here is only for lookup.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToolchainLock {
    inner: LockFile,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct LockFile {
    schema_version: u64,
    tog_version: String,
    toolchain: BTreeMap<String, EcoLock>,
}

impl ToolchainLock {
    /// Parse and strictly validate lock bytes.
    pub fn parse(bytes: &[u8]) -> io::Result<Self> {
        let text =
            std::str::from_utf8(bytes).map_err(|_| invalid("tog-toolchain.toml is not UTF-8"))?;
        let inner: LockFile =
            toml::from_str(text).map_err(|e| invalid(format!("tog-toolchain.toml: {e}")))?;
        let lock = Self { inner };
        lock.validate()?;
        Ok(lock)
    }

    fn validate(&self) -> io::Result<()> {
        if self.inner.schema_version != SCHEMA_VERSION {
            return Err(invalid(format!(
                "tog-toolchain.toml: unsupported schema_version {}",
                self.inner.schema_version
            )));
        }
        if self.inner.tog_version.is_empty() {
            return Err(invalid("tog-toolchain.toml: empty tog_version"));
        }
        if self.inner.toolchain.is_empty() {
            return Err(invalid("tog-toolchain.toml: no toolchain entries"));
        }
        for (eco, entry) in &self.inner.toolchain {
            let bad = |what: String| invalid(format!("tog-toolchain.toml [{eco}]: {what}"));
            if entry.runtime.is_empty() {
                return Err(bad("empty runtime".into()));
            }
            if entry.release.is_empty() {
                return Err(bad("empty release".into()));
            }
            if !is_digest(&entry.bundle_id) {
                return Err(bad(format!("bad bundle_id {:?}", entry.bundle_id)));
            }
            if entry.primary.is_empty() {
                return Err(bad("empty primary".into()));
            }
            if entry.components.is_empty() {
                return Err(bad("empty components".into()));
            }
            let names: std::collections::BTreeSet<&str> =
                entry.components.iter().map(String::as_str).collect();
            if names.len() != entry.components.len() {
                return Err(bad("duplicate component".into()));
            }
            for name in &entry.components {
                if !entry.component.contains_key(name.as_str()) {
                    return Err(bad(format!("component {name} has no table")));
                }
            }
            for (name, table) in &entry.component {
                if !names.contains(name.as_str()) {
                    return Err(bad(format!("table for unlisted component {name}")));
                }
                if table.version.is_empty() {
                    return Err(bad(format!("component {name} lacks a version")));
                }
                if let Some(parent) = table.embedded_in.as_deref() {
                    if !names.contains(parent) {
                        return Err(bad(format!(
                            "component {name} is embedded in unknown {parent}"
                        )));
                    }
                }
            }
            for input in &entry.inputs {
                if input.path.is_empty() || input.field.is_empty() {
                    return Err(bad("input lacks a path or field".into()));
                }
                let has_value = input.value.is_some();
                let absent = input.absent.unwrap_or(false);
                if has_value && absent {
                    return Err(bad(format!(
                        "input {} has both a value and absent = true",
                        input.path
                    )));
                }
                if !has_value && !absent {
                    return Err(bad(format!(
                        "input {} has neither a value nor absent = true",
                        input.path
                    )));
                }
            }
            for (triple, platform) in &entry.platforms {
                if platform.artifacts.is_empty() {
                    return Err(bad(format!("platform {triple} has no artifacts")));
                }
                for (component, row) in &platform.artifacts {
                    if !names.contains(component.as_str()) {
                        return Err(bad(format!(
                            "artifact row for unknown component {component}"
                        )));
                    }
                    if entry.component[component.as_str()].embedded_in.is_some() {
                        return Err(bad(format!(
                            "embedded component {component} has its own artifact row"
                        )));
                    }
                    if row.provider.is_empty()
                        || row.build.is_empty()
                        || row.recipe.is_empty()
                        || row.url.is_empty()
                    {
                        return Err(bad(format!(
                            "artifact row {triple}/{component} lacks provider, build, recipe or url"
                        )));
                    }
                    if !is_digest(&row.digest) {
                        return Err(bad(format!(
                            "artifact row {triple}/{component} has a bad digest"
                        )));
                    }
                }
            }
        }
        Ok(())
    }

    /// Canonical bytes: UTF-8, LF endings, one trailing newline, tables in
    /// schema order, arrays in stored order. A writer that follows it and a
    /// reader that re-serializes what it read produce the same bytes.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = String::new();
        out.push_str(&format!("schema_version = {}\n", self.inner.schema_version));
        out.push_str(&format!(
            "tog_version = {}\n",
            quoted(&self.inner.tog_version)
        ));
        for (eco, entry) in &self.inner.toolchain {
            out.push_str(&format!("\n[toolchain.{eco}]\n"));
            out.push_str(&format!("runtime = {}\n", quoted(&entry.runtime)));
            out.push_str(&format!("release = {}\n", quoted(&entry.release)));
            out.push_str(&format!("bundle_id = {}\n", quoted(&entry.bundle_id)));
            out.push_str(&format!("primary = {}\n", quoted(&entry.primary)));
            if let Some(revision) = entry.revision {
                out.push_str(&format!("revision = {revision}\n"));
            }
            out.push_str("components = [");
            for (i, name) in entry.components.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                out.push_str(&quoted(name));
            }
            out.push_str("]\n");
            for name in &entry.components {
                let table = &entry.component[name.as_str()];
                out.push_str(&format!("[toolchain.{eco}.component.{name}]\n"));
                out.push_str(&format!("version = {}\n", quoted(&table.version)));
                if let Some(parent) = table.embedded_in.as_deref() {
                    out.push_str(&format!("embedded_in = {}\n", quoted(parent)));
                }
            }
            for input in &entry.inputs {
                out.push_str(&format!("[[toolchain.{eco}.inputs]]\n"));
                out.push_str(&format!("path = {}\n", quoted(&input.path)));
                out.push_str(&format!("field = {}\n", quoted(&input.field)));
                if let Some(value) = input.value.as_deref() {
                    out.push_str(&format!("value = {}\n", quoted(value)));
                }
                if input.absent.unwrap_or(false) {
                    out.push_str("absent = true\n");
                }
                if let Some(sha) = input.sha256.as_deref() {
                    out.push_str(&format!("sha256 = {}\n", quoted(sha)));
                }
            }
            for (triple, platform) in &entry.platforms {
                for (component, row) in &platform.artifacts {
                    out.push_str(&format!(
                        "[toolchain.{eco}.platforms.{}.artifacts.{component}]\n",
                        quoted(triple)
                    ));
                    out.push_str(&format!("provider = {}\n", quoted(&row.provider)));
                    out.push_str(&format!("build = {}\n", quoted(&row.build)));
                    out.push_str(&format!("recipe = {}\n", quoted(&row.recipe)));
                    out.push_str(&format!("url = {}\n", quoted(&row.url)));
                    out.push_str(&format!("digest = {}\n", quoted(&row.digest)));
                }
            }
        }
        out.push('\n');
        out.into_bytes()
    }

    /// Read the lock through the held project root, or `None` when absent.
    /// A symlink at any component fails closed instead of being read through.
    pub fn read_via(root: &ProjectRoot) -> io::Result<Option<Self>> {
        match root.read_file(Path::new(LOCK_PATH))? {
            None => Ok(None),
            Some(bytes) => Self::parse(&bytes).map(Some),
        }
    }

    /// Ecosystems named in the lock.
    pub fn ecosystems(&self) -> Vec<&str> {
        self.inner.toolchain.keys().map(String::as_str).collect()
    }
}

fn is_digest(text: &str) -> bool {
    let (algo, hex) = match text.split_once(':') {
        Some(pair) => pair,
        None => return false,
    };
    if algo != "sha256" && algo != "sha512" {
        return false;
    }
    let len = if algo == "sha256" { 64 } else { 128 };
    hex.len() == len && hex.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Basic double-quoted string with no unnecessary escapes.
fn quoted(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04X}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// One staleness rule for every input row: re-derive the row and compare. A
/// row is stale when a value appears where the record has absent, when the
/// record has a value and re-derivation finds none, or when both have a
/// value and they differ. A differing file digest alone never decides; it
/// only forces the re-parse.
pub fn input_is_stale(recorded_value: Option<&str>, current_value: Option<&str>) -> bool {
    match (recorded_value, current_value) {
        (None, None) => false,
        (None, Some(_)) => true,
        (Some(_), None) => true,
        (Some(a), Some(b)) => a != b,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NODE_LOCK: &str = r#"schema_version = 1
tog_version = "0.1.0"

[toolchain.node]
runtime = "node"
release = "node-24.20.0-r1"
bundle_id = "sha256:683bc7a0c5d38d3fcc9e73a6e55ab75bda308fb66204c4808942e750b5c1266b"
primary = "node"
revision = 1
components = ["node", "bundled-npm", "node-gyp"]
[toolchain.node.component.node]
version = "24.20.0"
[toolchain.node.component.bundled-npm]
version = "11.19.0"
embedded_in = "node"
[toolchain.node.component.node-gyp]
version = "12.4.0"
embedded_in = "bundled-npm"
[[toolchain.node.inputs]]
path = ".node-version"
field = "version"
value = "24.20.0"
sha256 = "5b9d0e73029969ae9000117cb877f17bb9841c1279bfe8024e294acfcf017800"
[[toolchain.node.inputs]]
path = "package.json"
field = "engines.node"
absent = true
sha256 = "9f2c1a7c8b0a5f4e6d3b2718c9a04e5f1d6b83c27a4e90f5b1c8d3a672e4f0b9"
[toolchain.node.platforms."aarch64-apple-darwin".artifacts.node]
provider = "nodejs.org"
build = "24.20.0"
recipe = "nodejs/legacy"
url = "https://nodejs.org/dist/v24.20.0/node-v24.20.0-darwin-arm64.tar.gz"
digest = "sha256:40e5607e5ecb3db9192723776da2d75d966260fc74a7a9e731c1bd67dda96bc8"
[toolchain.node.platforms."x86_64-unknown-linux-gnu".artifacts.node]
provider = "nodejs.org"
build = "24.20.0"
recipe = "nodejs/legacy"
url = "https://nodejs.org/dist/v24.20.0/node-v24.20.0-linux-x64.tar.gz"
digest = "sha256:855d581f8a4eb1a8117e3426de25fe02770592febcfb31369aee1ffbfee9e8ec"

"#;

    #[test]
    fn node_lock_parses_and_round_trips() {
        let lock = ToolchainLock::parse(NODE_LOCK.as_bytes()).unwrap();
        assert_eq!(lock.ecosystems(), ["node"]);
        assert_eq!(lock.canonical_bytes(), NODE_LOCK.as_bytes());
        let again = ToolchainLock::parse(&lock.canonical_bytes()).unwrap();
        assert_eq!(again.canonical_bytes(), NODE_LOCK.as_bytes());
    }

    #[test]
    fn unknown_fields_and_bad_ids_fail() {
        let with_extra = NODE_LOCK.replace(
            "primary = \"node\"\n",
            "primary = \"node\"\nunknown_field = 1\n",
        );
        assert!(ToolchainLock::parse(with_extra.as_bytes()).is_err());
        let bad_id = NODE_LOCK.replace(
            "bundle_id = \"sha256:683bc7a0c5d38d3fcc9e73a6e55ab75bda308fb66204c4808942e750b5c1266b\"",
            "bundle_id = \"md5:abc\"",
        );
        assert!(ToolchainLock::parse(bad_id.as_bytes()).is_err());
        let both = NODE_LOCK.replace("absent = true\n", "absent = true\nvalue = \"24.20.0\"\n");
        assert!(ToolchainLock::parse(both.as_bytes()).is_err());
    }

    #[test]
    fn staleness_compares_values_not_digests() {
        assert!(!input_is_stale(None, None));
        assert!(input_is_stale(None, Some("24.20.0")));
        assert!(input_is_stale(Some("24.20.0"), None));
        assert!(!input_is_stale(Some("24.20.0"), Some("24.20.0")));
        assert!(input_is_stale(Some("24.20.0"), Some("24.22.0")));
    }

    #[test]
    fn lock_read_is_absent_when_no_file() {
        let temp = crate::kernel::testutil::TempDir::new();
        let dir = temp.0.join("proj");
        std::fs::create_dir_all(&dir).unwrap();
        let root = ProjectRoot::open(&dir).unwrap();
        assert!(ToolchainLock::read_via(&root).unwrap().is_none());
        std::fs::write(dir.join(LOCK_PATH), NODE_LOCK).unwrap();
        let lock = ToolchainLock::read_via(&root).unwrap().unwrap();
        assert_eq!(lock.ecosystems(), ["node"]);
    }
}

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
            if !is_bare_key(eco) {
                return Err(bad("ecosystem name is not a bare TOML key".into()));
            }
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
            if !entry.components.contains(&entry.primary) {
                return Err(bad(format!(
                    "primary {} is not a listed component",
                    entry.primary
                )));
            }
            if entry.inputs.is_empty() {
                return Err(bad("no inputs".into()));
            }
            if entry.platforms.is_empty() {
                return Err(bad("no platforms".into()));
            }
            let names: std::collections::BTreeSet<&str> =
                entry.components.iter().map(String::as_str).collect();
            if names.len() != entry.components.len() {
                return Err(bad("duplicate component".into()));
            }
            for name in &entry.components {
                if !is_bare_key(name) {
                    return Err(bad(format!(
                        "component name {name:?} is not a bare TOML key"
                    )));
                }
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
                // The embedding chain must reach an independently fetched
                // ancestor within the component count, or it is a cycle.
                let mut hops = 0;
                let mut cursor = table.embedded_in.as_deref();
                while let Some(parent) = cursor {
                    hops += 1;
                    if hops > entry.components.len() {
                        return Err(bad(format!("component {name} embedding is cyclic")));
                    }
                    cursor = entry
                        .component
                        .get(parent)
                        .and_then(|t| t.embedded_in.as_deref());
                }
            }
            for input in &entry.inputs {
                if input.path.is_empty() || input.field.is_empty() {
                    return Err(bad("input lacks a path or field".into()));
                }
                if !is_project_relative(&input.path) {
                    return Err(bad(format!(
                        "input path {:?} is not a normalized project-relative path",
                        input.path
                    )));
                }
                if input.absent == Some(false) {
                    return Err(bad(format!(
                        "input {} spells absent = false; omit the key instead",
                        input.path
                    )));
                }
                if let Some(sha) = input.sha256.as_deref() {
                    if !is_hex_of_length(sha, 64) {
                        return Err(bad(format!("input {} has a bad sha256", input.path)));
                    }
                }
                let has_value = input.value.is_some();
                if has_value && input.sha256.is_none() {
                    return Err(bad(format!(
                        "input {} has a value but no sha256",
                        input.path
                    )));
                }
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
                for name in &entry.components {
                    let embedded = entry.component[name.as_str()].embedded_in.is_some();
                    if !embedded && !platform.artifacts.contains_key(name.as_str()) {
                        return Err(bad(format!(
                            "platform {triple} lacks an artifact row for component {name}"
                        )));
                    }
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

/// A TOML bare key: the writer emits ecosystem and component names unquoted
/// in table headers, so every name it accepts must be one.
fn is_bare_key(text: &str) -> bool {
    !text.is_empty()
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn is_hex_of_length(text: &str, len: usize) -> bool {
    text.len() == len && text.bytes().all(|b| b.is_ascii_hexdigit())
}

fn is_digest(text: &str) -> bool {
    let (algo, hex) = match text.split_once(':') {
        Some(pair) => pair,
        None => return false,
    };
    match algo {
        "sha256" => is_hex_of_length(hex, 64),
        "sha512" => is_hex_of_length(hex, 128),
        _ => false,
    }
}

/// A normalized project-relative path: no leading slash, no `.` or `..`
/// component, no empty component, no backslash.
fn is_project_relative(text: &str) -> bool {
    !text.is_empty()
        && !text.contains('\\')
        && text
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
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
            c if (c as u32) < 0x20 || c == '\u{7F}' => {
                out.push_str(&format!("\\u{:04X}", c as u32))
            }
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
    fn names_the_writer_cannot_emit_bare_are_refused() {
        // The canonical writer puts ecosystem and component names in table
        // headers unquoted, so a name with a dot or quote would either
        // re-parse as a different key or not parse at all.
        let dotted_eco = NODE_LOCK.replace("[toolchain.node]", "[toolchain.\"no.de\"]");
        assert!(ToolchainLock::parse(dotted_eco.as_bytes()).is_err());
        let dotted_component = NODE_LOCK
            .replace("\"node-gyp\"", "\"node.gyp\"")
            .replace("component.node-gyp]", "component.\"node.gyp\"]");
        let error = ToolchainLock::parse(dotted_component.as_bytes()).unwrap_err();
        assert!(error.to_string().contains("bare TOML key"), "{error}");
    }

    #[test]
    fn control_characters_round_trip_through_quoting() {
        // Every TOML-forbidden literal, including U+007F, must be escaped,
        // or the canonical bytes would not parse again.
        for code in (0u32..0x20).chain([0x7F]) {
            let c = char::from_u32(code).unwrap();
            let text = format!("a{c}b");
            let quoted = quoted(&text);
            let parsed: toml::Value = toml::from_str(&format!("v = {quoted}")).unwrap();
            assert_eq!(parsed["v"].as_str(), Some(text.as_str()), "U+{code:04X}");
        }
        let with_del = NODE_LOCK.replace("tog_version = \"0.1.0\"", "tog_version = \"0.1\\u007F\"");
        let lock = ToolchainLock::parse(with_del.as_bytes()).unwrap();
        let again = ToolchainLock::parse(&lock.canonical_bytes()).unwrap();
        assert_eq!(again, lock);
    }

    #[test]
    fn structural_gaps_are_refused() {
        let cases: &[(&str, &str, &str)] = &[
            (
                "primary = \"node\"",
                "primary = \"npm\"",
                "not a listed component",
            ),
            (
                "embedded_in = \"bundled-npm\"",
                "embedded_in = \"node-gyp\"",
                "cyclic",
            ),
            (
                "path = \"package.json\"",
                "path = \"../package.json\"",
                "project-relative",
            ),
            ("absent = true\n", "absent = false\n", "absent = false"),
            (
                "sha256 = \"5b9d0e73029969ae9000117cb877f17bb9841c1279bfe8024e294acfcf017800\"\n",
                "",
                "value but no sha256",
            ),
            (
                "[toolchain.node.platforms.\"x86_64-unknown-linux-gnu\".artifacts.node]",
                "[toolchain.node.platforms.\"x86_64-unknown-linux-gnu\".artifacts.npm]",
                "lacks an artifact row",
            ),
        ];
        for (from, to, expect) in cases {
            let text = NODE_LOCK.replace(from, to);
            assert_ne!(text, NODE_LOCK, "{from} not found");
            let error = ToolchainLock::parse(text.as_bytes()).unwrap_err();
            assert!(error.to_string().contains(expect), "{from}: {error}");
        }
        let extra_row = |component: &str| {
            NODE_LOCK.trim_end().to_string()
                + &format!(
                    "\n[toolchain.node.platforms.\"x86_64-unknown-linux-gnu\".artifacts.{component}]\n"
                )
                + "provider = \"x\"\nbuild = \"x\"\nrecipe = \"x\"\nurl = \"x\"\n"
                + "digest = \"sha256:855d581f8a4eb1a8117e3426de25fe02770592febcfb31369aee1ffbfee9e8ec\"\n"
        };
        let embedded_row = extra_row("bundled-npm");
        let error = ToolchainLock::parse(embedded_row.as_bytes()).unwrap_err();
        assert!(error.to_string().contains("embedded component"), "{error}");
        let error = ToolchainLock::parse(extra_row("npm").as_bytes()).unwrap_err();
        assert!(error.to_string().contains("unknown component"), "{error}");
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

    #[test]
    fn lock_read_refuses_a_symlinked_file() {
        let temp = crate::kernel::testutil::TempDir::new();
        let dir = temp.0.join("proj");
        std::fs::create_dir_all(&dir).unwrap();
        let victim = temp.0.join("victim");
        std::fs::write(&victim, NODE_LOCK).unwrap();
        std::os::unix::fs::symlink(&victim, dir.join(LOCK_PATH)).unwrap();
        let root = ProjectRoot::open(&dir).unwrap();
        let error = ToolchainLock::read_via(&root).unwrap_err();
        assert!(error.to_string().contains("is a symlink"), "{error}");
    }
}

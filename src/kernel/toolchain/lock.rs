//! Committed toolchain lock: which exact toolchain each ecosystem uses.
//!
//! The file is `tog-toolchain.toml` next to the manifests, outside the
//! ignored `.tog/` directory. It records one bundle per ecosystem plus the
//! whole consulted input list, including sources that held no request, so a
//! new higher-precedence file flips a row from absent to present instead of
//! changing nothing the lock knows about.
//!
//! This module owns parsing, strict validation, and canonical writing.

use super::input::InputRow;
use super::{is_path_url, qualified, ArtifactRow, Bundle, Component, PATH_SOURCE};
use crate::kernel::digest::Digest;
use crate::kernel::fsroot::ProjectRoot;
use crate::kernel::platform::Platform;
use std::collections::BTreeMap;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

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
    /// `"path"` on the row of a toolchain that is a directory on this
    /// machine, absent on a catalog download. It is written from the row's
    /// `file://` URL and checked against it on read, so the two cannot
    /// disagree, and a lock with no path rows has the bytes it always had.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source: Option<String>,
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

/// `primary` is one component name or a list of them. One entry is written
/// and read as a bare string (`primary = "node"`), more as an array
/// (`primary = ["otp", "elixir"]`), so the two spellings are one value.
mod primary_serde {
    use serde::{Deserialize as _, Deserializer, Serialize as _, Serializer};

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        #[serde(untagged)]
        enum OneOrMany {
            One(String),
            Many(Vec<String>),
        }
        Ok(match OneOrMany::deserialize(deserializer)? {
            OneOrMany::One(name) => vec![name],
            OneOrMany::Many(names) => names,
        })
    }

    pub fn serialize<S>(names: &[String], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match names {
            [one] => one.serialize(serializer),
            many => many.serialize(serializer),
        }
    }
}

/// One ecosystem's row. The fields are private: a reader reconstructs the
/// kernel [`Bundle`] and the recorded [`InputRow`]s through the accessors
/// below, so no caller depends on the TOML shape.
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct EcoLock {
    runtime: String,
    release: String,
    bundle_id: String,
    #[serde(with = "primary_serde")]
    primary: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    revision: Option<u64>,
    components: Vec<String>,
    #[serde(default)]
    component: BTreeMap<String, ComponentLock>,
    /// The release pinned for each helper this ecosystem builds with, by
    /// helper lock ecosystem (`rust = "1.98.1"` in a Python section: the
    /// Rust its sdists compile with when the project locks no Rust). A
    /// section written before helpers were pinned has none, and its reader
    /// supplies the release that section's builds already used.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    helpers: BTreeMap<String, String>,
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
            for primary in &entry.primary {
                if !entry.components.contains(primary) {
                    return Err(bad(format!("primary {primary} is not a listed component")));
                }
            }
            if entry.inputs.is_empty() {
                return Err(bad("no inputs".into()));
            }
            if entry.platforms.is_empty() {
                return Err(bad("no platforms".into()));
            }
            for (helper, release) in &entry.helpers {
                if !is_bare_key(helper) || helper == eco {
                    return Err(bad(format!(
                        "helper name {helper:?} is not another ecosystem"
                    )));
                }
                if release.is_empty() {
                    return Err(bad(format!("helper {helper} has an empty release")));
                }
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
                if Platform::from_triple(triple).is_none() {
                    return Err(bad(format!("unsupported platform triple {triple:?}")));
                }
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
                    let marked = row.source.as_deref() == Some(PATH_SOURCE);
                    if row.source.is_some() && !marked {
                        return Err(bad(format!(
                            "artifact row {triple}/{component} has source {:?}; the only source a row names is {PATH_SOURCE:?}",
                            row.source.as_deref().unwrap_or_default()
                        )));
                    }
                    if marked != is_path_url(&row.url) {
                        return Err(bad(format!(
                            "artifact row {triple}/{component}: source = {PATH_SOURCE:?} goes with a file:// url and only with one"
                        )));
                    }
                }
            }
            // The id is a hash of the rows it stands beside. A row edited
            // by hand under the old id would otherwise pass every reader,
            // and `status` would call a closure built from the real bundle
            // current.
            let computed = entry.bundle()?.section_id(&entry.helpers);
            if computed != entry.bundle_id {
                return Err(bad(format!(
                    "bundle_id {} does not match its rows and helper pins ({computed}); the file was edited, \
                     run `tog update --toolchain {eco}`",
                    entry.bundle_id
                )));
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
            match entry.primary.as_slice() {
                [one] => out.push_str(&format!("primary = {}\n", quoted(one))),
                many => {
                    out.push_str("primary = [");
                    for (i, name) in many.iter().enumerate() {
                        if i > 0 {
                            out.push_str(", ");
                        }
                        out.push_str(&quoted(name));
                    }
                    out.push_str("]\n");
                }
            }
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
            if !entry.helpers.is_empty() {
                out.push_str(&format!("[toolchain.{eco}.helpers]\n"));
                for (helper, release) in &entry.helpers {
                    out.push_str(&format!("{helper} = {}\n", quoted(release)));
                }
            }
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
                    if let Some(source) = row.source.as_deref() {
                        out.push_str(&format!("source = {}\n", quoted(source)));
                    }
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

    /// The raw lock bytes, or `None` when the file is absent. The bytes a
    /// caller compares before publishing come from here, never from a
    /// re-serialized parse tree.
    pub fn read_bytes_via(root: &ProjectRoot) -> io::Result<Option<Vec<u8>>> {
        root.read_file(Path::new(LOCK_PATH))
    }

    /// Ecosystems named in the lock.
    pub fn ecosystems(&self) -> Vec<&str> {
        self.inner.toolchain.keys().map(String::as_str).collect()
    }

    /// One ecosystem's row, or `None` when the lock has no section for it.
    pub fn ecosystem(&self, name: &str) -> Option<&EcoLock> {
        self.inner.toolchain.get(name)
    }

    /// An empty lock for `tog_version`. It is not valid until at least one
    /// ecosystem has been set: a lock with no toolchain entry states nothing.
    pub fn new(tog_version: &str) -> ToolchainLock {
        ToolchainLock {
            inner: LockFile {
                schema_version: SCHEMA_VERSION,
                tog_version: tog_version.to_string(),
                toolchain: BTreeMap::new(),
            },
        }
    }

    /// Record `bundle` and the consulted `inputs` as this ecosystem's
    /// section, replacing one that is already there, then validate the whole
    /// lock. That replacement is what an update writes.
    pub fn set_ecosystem(
        &mut self,
        ecosystem: &str,
        bundle: &Bundle,
        inputs: &[InputRow],
    ) -> io::Result<()> {
        let runtime = bundle
            .primary
            .first()
            .ok_or_else(|| invalid(format!("release {}: no primary component", bundle.release)))?
            .clone();
        let mut components = Vec::new();
        let mut component = BTreeMap::new();
        for entry in &bundle.components {
            components.push(entry.name.clone());
            component.insert(
                entry.name.clone(),
                ComponentLock {
                    version: entry.version.clone(),
                    embedded_in: entry.embedded_in.clone(),
                },
            );
        }
        let mut platforms: BTreeMap<String, PlatformLock> = BTreeMap::new();
        for row in &bundle.artifacts {
            platforms
                .entry(row.platform.triple().to_string())
                .or_insert_with(|| PlatformLock {
                    artifacts: BTreeMap::new(),
                })
                .artifacts
                .insert(
                    row.component.clone(),
                    ArtifactLock {
                        source: is_path_url(&row.url).then(|| PATH_SOURCE.to_string()),
                        provider: row.provider.clone(),
                        build: row.build.clone(),
                        recipe: row.recipe.clone(),
                        url: row.url.clone(),
                        digest: qualified(&row.digest),
                    },
                );
        }
        let mut rows = Vec::new();
        for row in inputs {
            let path = row.path.to_str().ok_or_else(|| {
                invalid(format!("input path {:?} is not UTF-8", row.path.display()))
            })?;
            rows.push(InputToml {
                path: path.to_string(),
                field: row.field.clone(),
                value: row.value.clone(),
                absent: row.absent.then_some(true),
                sha256: row.sha256.clone(),
            });
        }
        self.inner.toolchain.insert(
            ecosystem.to_string(),
            EcoLock {
                runtime,
                release: bundle.release.clone(),
                bundle_id: bundle.bundle_id(),
                primary: bundle.primary.clone(),
                revision: bundle.revision.map(u64::from),
                components,
                component,
                helpers: BTreeMap::new(),
                inputs: rows,
                platforms,
            },
        );
        self.validate()
    }

    /// Pin the helper releases of `ecosystem`'s section (see
    /// [`EcoLock::helpers`]), replacing any it had, then validate the whole
    /// lock. The section must already be set.
    pub fn set_helpers(
        &mut self,
        ecosystem: &str,
        helpers: &BTreeMap<String, String>,
    ) -> io::Result<()> {
        let entry =
            self.inner.toolchain.get_mut(ecosystem).ok_or_else(|| {
                invalid(format!("tog-toolchain.toml has no [{ecosystem}] section"))
            })?;
        entry.helpers = helpers.clone();
        entry.bundle_id = entry.bundle()?.section_id(helpers);
        self.validate()
    }

    /// Publish the canonical bytes at `tog-toolchain.toml` through the held
    /// project root: an `O_EXCL` temporary on a random name, the file
    /// fsynced, renamed descriptor-relative, and the directory fsynced.
    pub fn publish_via(&self, root: &ProjectRoot) -> io::Result<()> {
        root.write_file(Path::new(LOCK_PATH), &self.canonical_bytes())
    }
}

impl EcoLock {
    /// The component whose version names the runtime: the first primary.
    // Read by tests/toolchain_lock.rs, outside lib.rs's `boundary` reach.
    #[cfg_attr(tog_dead_code, allow(dead_code))]
    pub fn runtime(&self) -> &str {
        &self.runtime
    }

    /// The catalog release key this section was minted from. Provenance,
    /// never a key honoring the lock looks up.
    // Read by tests/toolchain_lock.rs, outside lib.rs's `boundary` reach.
    #[cfg_attr(tog_dead_code, allow(dead_code))]
    pub fn release(&self) -> &str {
        &self.release
    }

    pub fn bundle_id(&self) -> &str {
        &self.bundle_id
    }

    #[cfg(test)]
    /// The primary component(s), in comparison order.
    pub fn primary(&self) -> &[String] {
        &self.primary
    }

    /// The helper releases this section pins, by helper lock ecosystem.
    /// Empty for a section written before helpers were pinned.
    pub fn helpers(&self) -> &BTreeMap<String, String> {
        &self.helpers
    }

    /// The kernel [`Bundle`] this section records: the locked rows, not a
    /// catalog lookup. An unknown platform triple or digest algorithm is an
    /// error rather than a row honoring replay would skip.
    pub fn bundle(&self) -> io::Result<Bundle> {
        let revision = match self.revision {
            None => None,
            Some(value) => Some(u32::try_from(value).map_err(|_| {
                invalid(format!(
                    "tog-toolchain.toml [{}]: revision {value} is out of range",
                    self.release
                ))
            })?),
        };
        let components = self
            .components
            .iter()
            .map(|name| {
                let table = self.component.get(name.as_str()).ok_or_else(|| {
                    invalid(format!("tog-toolchain.toml: component {name} has no table"))
                })?;
                Ok(Component {
                    name: name.clone(),
                    version: table.version.clone(),
                    embedded_in: table.embedded_in.clone(),
                })
            })
            .collect::<io::Result<Vec<_>>>()?;
        let mut artifacts = Vec::new();
        for (triple, platform) in &self.platforms {
            let host = Platform::from_triple(triple).ok_or_else(|| {
                invalid(format!(
                    "tog-toolchain.toml: unsupported platform triple {triple:?}"
                ))
            })?;
            for (component, row) in &platform.artifacts {
                artifacts.push(ArtifactRow {
                    platform: host,
                    component: component.clone(),
                    provider: row.provider.clone(),
                    build: row.build.clone(),
                    recipe: row.recipe.clone(),
                    url: row.url.clone(),
                    digest: parse_digest(&row.digest)?,
                });
            }
        }
        Ok(Bundle {
            release: self.release.clone(),
            revision,
            primary: self.primary.clone(),
            components,
            artifacts,
        })
    }

    /// The consulted sources as recorded, in lock order: what staleness
    /// compares today's discovery against.
    pub fn inputs(&self) -> Vec<InputRow> {
        self.inputs
            .iter()
            .map(|row| InputRow {
                path: PathBuf::from(&row.path),
                field: row.field.clone(),
                value: row.value.clone(),
                absent: row.absent.unwrap_or(false),
                sha256: row.sha256.clone(),
            })
            .collect()
    }
}

/// `<algorithm>:<hex>` back to a [`Digest`]. Validation already refused any
/// other spelling, so an error here means the row was built, not parsed.
fn parse_digest(text: &str) -> io::Result<Digest> {
    super::parse_qualified(text)
}

/// One recorded source row that no longer matches the project.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StaleRow {
    pub path: String,
    pub field: String,
    pub recorded: Option<String>,
    pub current: Option<String>,
}

impl fmt::Display for StaleRow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let spell = |value: &Option<String>| match value {
            Some(text) => text.clone(),
            None => "absent".to_string(),
        };
        write!(
            f,
            "{} {}: recorded {}, now {}",
            self.path,
            self.field,
            spell(&self.recorded),
            spell(&self.current)
        )
    }
}

/// Every row on which the record and today's discovery disagree. Rows pair
/// by (path, field); a row only one side has is stale on its own, because
/// the consulted list is a complete statement about the project.
pub fn stale_rows(recorded: &[InputRow], current: &[InputRow]) -> Vec<StaleRow> {
    let key = |row: &InputRow| (row.path.to_string_lossy().into_owned(), row.field.clone());
    let mut out = Vec::new();
    for row in recorded {
        let (path, field) = key(row);
        match current
            .iter()
            .find(|other| key(other) == (path.clone(), field.clone()))
        {
            None => out.push(StaleRow {
                path,
                field,
                recorded: row.value.clone(),
                current: None,
            }),
            Some(other) if input_is_stale(row.value.as_deref(), other.value.as_deref()) => out
                .push(StaleRow {
                    path,
                    field,
                    recorded: row.value.clone(),
                    current: other.value.clone(),
                }),
            Some(_) => {}
        }
    }
    for row in current {
        let (path, field) = key(row);
        // A row the lock never recorded (a source a later tog consults)
        // changes nothing while it states no value: only one that asks for
        // something makes the lock stale.
        if row.value.is_some()
            && !recorded
                .iter()
                .any(|other| key(other) == (path.clone(), field.clone()))
        {
            out.push(StaleRow {
                path,
                field,
                recorded: None,
                current: row.value.clone(),
            });
        }
    }
    out
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

    pub(super) const NODE_LOCK: &str = r#"schema_version = 1
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
        let error = ToolchainLock::parse(with_extra.as_bytes()).unwrap_err();
        assert!(
            error.to_string().contains("unknown field `unknown_field`"),
            "{error}"
        );
        // Refused by the digest-shape check itself, before the id is ever
        // recomputed from the rows (which would also disagree).
        let bad_id = NODE_LOCK.replace(
            "bundle_id = \"sha256:683bc7a0c5d38d3fcc9e73a6e55ab75bda308fb66204c4808942e750b5c1266b\"",
            "bundle_id = \"md5:abc\"",
        );
        let error = ToolchainLock::parse(bad_id.as_bytes()).unwrap_err();
        assert_eq!(
            error.to_string(),
            "tog-toolchain.toml [node]: bad bundle_id \"md5:abc\""
        );
        let both = NODE_LOCK.replace("absent = true\n", "absent = true\nvalue = \"24.20.0\"\n");
        let error = ToolchainLock::parse(both.as_bytes()).unwrap_err();
        assert_eq!(
            error.to_string(),
            "tog-toolchain.toml [node]: input package.json has both a value and absent = true"
        );
    }

    #[test]
    fn names_the_writer_cannot_emit_bare_are_refused() {
        // The canonical writer puts ecosystem and component names in table
        // headers unquoted, so a name with a dot or quote would either
        // re-parse as a different key or not parse at all.
        // Every table under the ecosystem moves with it, so the TOML shape
        // stays whole and only the name check can refuse.
        let dotted_eco = NODE_LOCK.replace("toolchain.node", "toolchain.\"no.de\"");
        let error = ToolchainLock::parse(dotted_eco.as_bytes()).unwrap_err();
        assert_eq!(
            error.to_string(),
            "tog-toolchain.toml [no.de]: ecosystem name is not a bare TOML key"
        );
        let dotted_component = NODE_LOCK
            .replace("\"node-gyp\"", "\"node.gyp\"")
            .replace("component.node-gyp]", "component.\"node.gyp\"]");
        let error = ToolchainLock::parse(dotted_component.as_bytes()).unwrap_err();
        assert_eq!(
            error.to_string(),
            "tog-toolchain.toml [node]: component name \"node.gyp\" is not a bare TOML key"
        );
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
                "primary npm is not a listed component",
            ),
            (
                "embedded_in = \"bundled-npm\"",
                "embedded_in = \"node-gyp\"",
                "component node-gyp embedding is cyclic",
            ),
            (
                "path = \"package.json\"",
                "path = \"../package.json\"",
                "input path \"../package.json\" is not a normalized project-relative path",
            ),
            (
                "absent = true\n",
                "absent = false\n",
                "input package.json spells absent = false; omit the key instead",
            ),
            (
                "sha256 = \"5b9d0e73029969ae9000117cb877f17bb9841c1279bfe8024e294acfcf017800\"\n",
                "",
                "input .node-version has a value but no sha256",
            ),
            (
                "[toolchain.node.platforms.\"x86_64-unknown-linux-gnu\".artifacts.node]",
                "[toolchain.node.platforms.\"x86_64-unknown-linux-gnu\".artifacts.npm]",
                "platform x86_64-unknown-linux-gnu lacks an artifact row for component node",
            ),
        ];
        for (from, to, expect) in cases {
            let text = NODE_LOCK.replace(from, to);
            assert_ne!(text, NODE_LOCK, "{from} not found");
            let error = ToolchainLock::parse(text.as_bytes()).unwrap_err();
            assert_eq!(
                error.to_string(),
                format!("tog-toolchain.toml [node]: {expect}"),
                "{from}"
            );
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
        assert_eq!(
            error.to_string(),
            "tog-toolchain.toml [node]: embedded component bundled-npm has its own artifact row"
        );
        let error = ToolchainLock::parse(extra_row("npm").as_bytes()).unwrap_err();
        assert_eq!(
            error.to_string(),
            "tog-toolchain.toml [node]: artifact row for unknown component npm"
        );
    }

    fn input(path: &str, field: &str, value: Option<&str>, sha256: Option<&str>) -> InputRow {
        InputRow {
            path: PathBuf::from(path),
            field: field.to_string(),
            value: value.map(str::to_string),
            absent: value.is_none(),
            sha256: sha256.map(str::to_string),
        }
    }

    /// The design's Node release, exactly as the example lock records it.
    fn node_bundle() -> Bundle {
        Bundle {
            release: "node-24.20.0-r1".into(),
            revision: Some(1),
            primary: vec!["node".into()],
            components: vec![
                Component::new("node", "24.20.0"),
                Component::embedded("bundled-npm", "11.19.0", "node"),
                Component::embedded("node-gyp", "12.4.0", "bundled-npm"),
            ],
            artifacts: vec![
                ArtifactRow::new(
                    Platform::Aarch64AppleDarwin,
                    "node",
                    "nodejs.org",
                    "24.20.0",
                    "nodejs/legacy",
                    "https://nodejs.org/dist/v24.20.0/node-v24.20.0-darwin-arm64.tar.gz",
                    Digest::sha256(
                        "40e5607e5ecb3db9192723776da2d75d966260fc74a7a9e731c1bd67dda96bc8",
                    )
                    .unwrap(),
                ),
                ArtifactRow::new(
                    Platform::X86_64UnknownLinuxGnu,
                    "node",
                    "nodejs.org",
                    "24.20.0",
                    "nodejs/legacy",
                    "https://nodejs.org/dist/v24.20.0/node-v24.20.0-linux-x64.tar.gz",
                    Digest::sha256(
                        "855d581f8a4eb1a8117e3426de25fe02770592febcfb31369aee1ffbfee9e8ec",
                    )
                    .unwrap(),
                ),
            ],
        }
    }

    fn node_inputs() -> Vec<InputRow> {
        vec![
            input(
                ".node-version",
                "version",
                Some("24.20.0"),
                Some("5b9d0e73029969ae9000117cb877f17bb9841c1279bfe8024e294acfcf017800"),
            ),
            input(
                "package.json",
                "engines.node",
                None,
                Some("9f2c1a7c8b0a5f4e6d3b2718c9a04e5f1d6b83c27a4e90f5b1c8d3a672e4f0b9"),
            ),
        ]
    }

    /// A bundle whose two primary components make the BEAM pair, with one
    /// artifact row per platform and component.
    fn beam_bundle() -> Bundle {
        let row = |platform: Platform, component: &str, fill: char| {
            ArtifactRow::new(
                platform,
                component,
                "example.org",
                "build",
                "beam/1",
                &format!("https://example.org/{}/{component}", platform.triple()),
                Digest::sha256(&fill.to_string().repeat(64)).unwrap(),
            )
        };
        Bundle {
            release: "beam-27.3.4-1.18.4".into(),
            revision: None,
            primary: vec!["otp".into(), "elixir".into()],
            components: vec![
                Component::new("otp", "27.3.4"),
                Component::new("elixir", "1.18.4"),
            ],
            artifacts: vec![
                row(Platform::Aarch64AppleDarwin, "elixir", 'a'),
                row(Platform::Aarch64AppleDarwin, "otp", 'b'),
                row(Platform::X86_64UnknownLinuxGnu, "elixir", 'c'),
                row(Platform::X86_64UnknownLinuxGnu, "otp", 'd'),
            ],
        }
    }

    #[test]
    fn the_builder_reproduces_the_design_example_bytes() {
        let mut lock = ToolchainLock::new("0.1.0");
        lock.set_ecosystem("node", &node_bundle(), &node_inputs())
            .unwrap();
        assert_eq!(
            String::from_utf8(lock.canonical_bytes()).unwrap(),
            NODE_LOCK
        );
    }

    #[test]
    fn a_built_lock_round_trips_back_to_its_bundle() {
        for bundle in [node_bundle(), beam_bundle(), path_bundle()] {
            let mut lock = ToolchainLock::new("0.1.0");
            lock.set_ecosystem("eco", &bundle, &node_inputs()).unwrap();
            let again = ToolchainLock::parse(&lock.canonical_bytes()).unwrap();
            assert_eq!(again.canonical_bytes(), lock.canonical_bytes());
            let section = again.ecosystem("eco").unwrap();
            assert_eq!(section.bundle().unwrap(), bundle);
            assert_eq!(section.bundle().unwrap().bundle_id(), bundle.bundle_id());
            assert_eq!(section.bundle_id(), bundle.bundle_id());
            assert_eq!(section.runtime(), bundle.primary[0]);
            assert_eq!(section.release(), bundle.release);
            assert_eq!(section.primary(), bundle.primary.as_slice());
            assert_eq!(section.inputs(), node_inputs());
        }
    }

    /// A toolchain that is a directory on this machine: one host row whose
    /// URL is the tree and whose digest is its content hash.
    fn path_bundle() -> Bundle {
        Bundle {
            release: "path".into(),
            revision: None,
            primary: vec!["rustc".into()],
            components: vec![
                Component::new("rustc", "1.96.1"),
                Component::embedded("cargo", "1.96.1", "rustc"),
            ],
            artifacts: vec![ArtifactRow::new(
                Platform::X86_64UnknownLinuxGnu,
                "rustc",
                "path",
                "rustc 1.96.1 (31fca3adb 2026-06-26); cargo 1.96.1 (356927216 2026-06-26)",
                "rust-path/1",
                "file:///custom/rust",
                Digest::sha256(&"e".repeat(64)).unwrap(),
            )],
        }
    }

    #[test]
    fn a_path_row_is_marked_by_its_source_and_round_trips() {
        let mut lock = ToolchainLock::new("0.1.0");
        lock.set_ecosystem("rust", &path_bundle(), &node_inputs())
            .unwrap();
        let text = String::from_utf8(lock.canonical_bytes()).unwrap();
        assert!(
            text.contains(
                "[toolchain.rust.platforms.\"x86_64-unknown-linux-gnu\".artifacts.rustc]\n\
                 source = \"path\"\nprovider = \"path\"\n"
            ),
            "{text}"
        );
        let again = ToolchainLock::parse(text.as_bytes()).unwrap();
        assert_eq!(again.canonical_bytes(), text.as_bytes());
        assert_eq!(
            again.ecosystem("rust").unwrap().bundle().unwrap(),
            path_bundle()
        );
        // A catalog row is never marked, so an existing lock keeps its bytes.
        let mut catalog = ToolchainLock::new("0.1.0");
        catalog
            .set_ecosystem("node", &node_bundle(), &node_inputs())
            .unwrap();
        assert!(!String::from_utf8(catalog.canonical_bytes())
            .unwrap()
            .contains("source ="));
        // The marker and the URL cannot disagree, and no other source exists.
        for (from, to, words) in [
            ("source = \"path\"\n", "", "goes with a file:// url"),
            (
                "url = \"file:///custom/rust\"",
                "url = \"https://example.org/rust\"",
                "goes with a file:// url",
            ),
            (
                "source = \"path\"",
                "source = \"catalog\"",
                "the only source a row names",
            ),
        ] {
            let edited = text.replacen(from, to, 1);
            let error = ToolchainLock::parse(edited.as_bytes())
                .unwrap_err()
                .to_string();
            assert!(error.contains(words), "{from} -> {to}: {error}");
        }
    }

    /// A section's helper pins are a table of their own, written only when
    /// there are some: a lock without them keeps the bytes it always had.
    #[test]
    fn helper_pins_round_trip_and_are_absent_when_empty() {
        let mut lock = ToolchainLock::new("0.1.0");
        lock.set_ecosystem("node", &node_bundle(), &node_inputs())
            .unwrap();
        let plain = lock.canonical_bytes();
        assert!(!String::from_utf8(plain.clone())
            .unwrap()
            .contains("helpers"));
        assert!(lock.ecosystem("node").unwrap().helpers().is_empty());
        let pins = BTreeMap::from([("python".to_string(), "3.12.14".to_string())]);
        lock.set_helpers("node", &pins).unwrap();
        let text = String::from_utf8(lock.canonical_bytes()).unwrap();
        assert!(
            text.contains("]\n[toolchain.node.helpers]\npython = \"3.12.14\"\n"),
            "{text}"
        );
        let again = ToolchainLock::parse(text.as_bytes()).unwrap();
        assert_eq!(again.canonical_bytes(), text.as_bytes());
        assert_eq!(again.ecosystem("node").unwrap().helpers(), &pins);
        // The section's id covers them.
        let section = again.ecosystem("node").unwrap();
        assert_eq!(
            section.bundle_id(),
            node_bundle().section_id(&pins),
            "{text}"
        );
        assert_ne!(section.bundle_id(), node_bundle().bundle_id());
        // Emptying them restores the original bytes.
        lock.set_helpers("node", &BTreeMap::new()).unwrap();
        assert_eq!(lock.canonical_bytes(), plain);
        // A helper is another ecosystem, with a release.
        for (from, to, words) in [
            ("python = \"3.12.14\"", "python = \"\"", "empty release"),
            (
                "python = \"3.12.14\"",
                "node = \"1\"",
                "not another ecosystem",
            ),
            (
                "python = \"3.12.14\"",
                "python = \"3.12.13\"",
                "does not match its rows and helper pins",
            ),
        ] {
            let edited = text.replacen(from, to, 1);
            let error = ToolchainLock::parse(edited.as_bytes())
                .unwrap_err()
                .to_string();
            assert!(error.contains(words), "{from} -> {to}: {error}");
        }
        assert!(lock.set_helpers("python", &pins).is_err());
    }

    #[test]
    fn an_edited_row_under_the_old_bundle_id_is_refused() {
        let mut lock = ToolchainLock::new("0.1.0");
        lock.set_ecosystem("node", &node_bundle(), &node_inputs())
            .unwrap();
        let text = String::from_utf8(lock.canonical_bytes()).unwrap();
        let (digest_line, _) = text
            .lines()
            .map(|line| (line, ()))
            .find(|(line, _)| line.starts_with("digest = "))
            .unwrap();
        let edited = text.replacen(
            digest_line,
            "digest = \"sha256:00000000000000000000000000000000000000000000000000000000000000ff\"",
            1,
        );
        let error = ToolchainLock::parse(edited.as_bytes())
            .unwrap_err()
            .to_string();
        assert!(error.contains("[node]: bundle_id"), "{error}");
        assert!(error.contains("does not match its rows"), "{error}");
        assert!(
            error.contains("run `tog update --toolchain node`"),
            "{error}"
        );

        // Dropping a whole platform table changes the rows the same way.
        let mut kept = String::new();
        let mut skipping = false;
        for line in text.lines() {
            if line.starts_with("[toolchain.node.platforms.") {
                skipping = line.contains("aarch64-apple-darwin");
            }
            if !skipping {
                kept.push_str(line);
                kept.push('\n');
            }
        }
        assert_ne!(kept, text);
        let error = ToolchainLock::parse(kept.as_bytes())
            .unwrap_err()
            .to_string();
        assert!(error.contains("does not match its rows"), "{error}");
    }

    #[test]
    fn a_primary_pair_is_written_and_read_as_an_array() {
        let mut lock = ToolchainLock::new("0.1.0");
        lock.set_ecosystem("elixir", &beam_bundle(), &node_inputs())
            .unwrap();
        let text = String::from_utf8(lock.canonical_bytes()).unwrap();
        assert!(text.contains("primary = [\"otp\", \"elixir\"]\n"), "{text}");
        let again = ToolchainLock::parse(text.as_bytes()).unwrap();
        assert_eq!(
            again.ecosystem("elixir").unwrap().primary(),
            ["otp", "elixir"]
        );
        assert_eq!(again.canonical_bytes(), text.as_bytes());
        // One primary keeps the bare-string spelling the design golden uses.
        let mut single = ToolchainLock::new("0.1.0");
        single
            .set_ecosystem("node", &node_bundle(), &node_inputs())
            .unwrap();
        let text = String::from_utf8(single.canonical_bytes()).unwrap();
        assert!(text.contains("primary = \"node\"\n"), "{text}");
    }

    #[test]
    fn setting_an_ecosystem_twice_replaces_its_section() {
        let mut lock = ToolchainLock::new("0.1.0");
        lock.set_ecosystem("node", &node_bundle(), &node_inputs())
            .unwrap();
        let mut newer = node_bundle();
        newer.release = "node-24.21.0-r1".into();
        newer.components[0].version = "24.21.0".into();
        lock.set_ecosystem("node", &newer, &node_inputs()).unwrap();
        assert_eq!(lock.ecosystems(), ["node"]);
        assert_eq!(lock.ecosystem("node").unwrap().bundle().unwrap(), newer);
        // A primary that is not a listed component is refused by the same
        // validation a parsed file goes through.
        let mut broken = node_bundle();
        broken.primary = vec!["npm".into()];
        let error = lock
            .set_ecosystem("node", &broken, &node_inputs())
            .unwrap_err();
        assert!(
            error.to_string().contains("not a listed component"),
            "{error}"
        );
    }

    #[test]
    fn stale_rows_pair_by_path_and_field_and_spell_absence() {
        let recorded = vec![
            input(
                ".python-version",
                "version",
                Some("3.12.14"),
                Some(&"a".repeat(64)),
            ),
            input("pyproject.toml", "project.requires-python", None, None),
            input("gone.toml", "field", Some("1"), Some(&"b".repeat(64))),
        ];
        let current = vec![
            input(
                ".python-version",
                "version",
                Some("3.13.15"),
                Some(&"c".repeat(64)),
            ),
            input(
                "pyproject.toml",
                "project.requires-python",
                Some(">=3.13"),
                Some(&"d".repeat(64)),
            ),
            input("new.toml", "field", Some("2"), Some(&"e".repeat(64))),
        ];
        let rows = stale_rows(&recorded, &current);
        let spelled: Vec<String> = rows.iter().map(ToString::to_string).collect();
        assert_eq!(
            spelled,
            [
                ".python-version version: recorded 3.12.14, now 3.13.15",
                "pyproject.toml project.requires-python: recorded absent, now >=3.13",
                "gone.toml field: recorded 1, now absent",
                "new.toml field: recorded absent, now 2",
            ]
        );
        // A row whose value is unchanged is not stale, whatever its digest.
        let same = [input(
            ".python-version",
            "version",
            Some("3.12.14"),
            Some(&"z".repeat(64)),
        )];
        assert!(stale_rows(&same[..1], &recorded[..1]).is_empty());
        // Nor is a row that was absent and still is.
        let absent = [input(
            "pyproject.toml",
            "project.requires-python",
            None,
            None,
        )];
        assert!(stale_rows(&absent, &recorded[1..2]).is_empty());
        // A source the lock never recorded (one a later tog consults) leaves
        // the lock fresh while it states nothing, and stales it once it does.
        let later = [input("setup.py", "python_requires", None, None)];
        assert!(stale_rows(&recorded[..1], &[&recorded[..1], &later[..]].concat()).is_empty());
        let stated = [input(
            "setup.py",
            "python_requires",
            Some("<3.12"),
            Some(&"f".repeat(64)),
        )];
        assert_eq!(
            stale_rows(&recorded[..1], &[&recorded[..1], &stated[..]].concat())
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            ["setup.py python_requires: recorded absent, now <3.12"]
        );
    }

    #[test]
    fn publication_writes_the_canonical_bytes_through_the_held_root() {
        let temp = crate::kernel::testutil::TempDir::new();
        let dir = temp.0.join("proj");
        std::fs::create_dir_all(&dir).unwrap();
        let root = ProjectRoot::open(&dir).unwrap();
        assert!(ToolchainLock::read_bytes_via(&root).unwrap().is_none());
        let mut lock = ToolchainLock::new("0.1.0");
        lock.set_ecosystem("node", &node_bundle(), &node_inputs())
            .unwrap();
        lock.publish_via(&root).unwrap();
        assert_eq!(
            ToolchainLock::read_bytes_via(&root).unwrap().unwrap(),
            lock.canonical_bytes()
        );
        assert_eq!(
            std::fs::read(dir.join(LOCK_PATH)).unwrap(),
            NODE_LOCK.as_bytes()
        );
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

/// Offline tests for the lock validator's refusals (#348). `validate` runs
/// inside `ToolchainLock::parse`, so each case is the design example with
/// one thing wrong, and each asserts the exact message. The structural
/// checks run before the bundle_id is recomputed, so an edit is refused for
/// what is wrong with it, not for the id it invalidates.
#[cfg(test)]
mod validate_tests {
    use super::tests::NODE_LOCK;
    use super::*;

    /// The fixture with `from` replaced by `to`. The needle must occur
    /// exactly once, so the edit lands where the test says it does.
    fn edited(from: &str, to: &str) -> String {
        assert_eq!(
            NODE_LOCK.matches(from).count(),
            1,
            "{from:?} must occur exactly once in the fixture"
        );
        NODE_LOCK.replacen(from, to, 1)
    }

    fn refusal(text: &str) -> String {
        ToolchainLock::parse(text.as_bytes())
            .map(drop)
            .expect_err("the edited lock must be refused")
            .to_string()
    }

    /// The fixture with everything from `marker` on cut off.
    fn cut_from(marker: &str) -> String {
        let at = NODE_LOCK.find(marker).expect("marker in the fixture");
        NODE_LOCK[..at].to_string()
    }

    #[test]
    fn the_file_header_is_checked_first() {
        assert_eq!(
            refusal(&edited("schema_version = 1", "schema_version = 2")),
            "tog-toolchain.toml: unsupported schema_version 2"
        );
        assert_eq!(
            refusal(&edited("tog_version = \"0.1.0\"", "tog_version = \"\"")),
            "tog-toolchain.toml: empty tog_version"
        );
        // An empty table, not a missing one: serde refuses the latter
        // before the validator sees it.
        assert_eq!(
            refusal(&format!("{}[toolchain]\n", cut_from("[toolchain.node]"))),
            "tog-toolchain.toml: no toolchain entries"
        );
    }

    #[test]
    fn a_section_missing_a_part_is_refused_by_name() {
        for (from, to, message) in [
            ("runtime = \"node\"", "runtime = \"\"", "empty runtime"),
            (
                "release = \"node-24.20.0-r1\"",
                "release = \"\"",
                "empty release",
            ),
            ("primary = \"node\"", "primary = []", "empty primary"),
            (
                "components = [\"node\", \"bundled-npm\", \"node-gyp\"]",
                "components = []",
                "empty components",
            ),
            (
                "components = [\"node\", \"bundled-npm\", \"node-gyp\"]",
                "components = [\"node\", \"node\", \"bundled-npm\", \"node-gyp\"]",
                "duplicate component",
            ),
            (
                "components = [\"node\", \"bundled-npm\", \"node-gyp\"]",
                "components = [\"node\", \"bundled npm\", \"node-gyp\"]",
                "component name \"bundled npm\" is not a bare TOML key",
            ),
            (
                "components = [\"node\", \"bundled-npm\", \"node-gyp\"]",
                "components = [\"node\", \"bundled-npm\", \"node-gyp\", \"extra\"]",
                "component extra has no table",
            ),
            (
                "version = \"12.4.0\"",
                "version = \"\"",
                "component node-gyp lacks a version",
            ),
            (
                "embedded_in = \"bundled-npm\"",
                "embedded_in = \"ghost\"",
                "component node-gyp is embedded in unknown ghost",
            ),
        ] {
            assert_eq!(
                refusal(&edited(from, to)),
                format!("tog-toolchain.toml [node]: {message}"),
                "{from} -> {to}"
            );
        }
        // A table for a component the list does not name.
        let unlisted = edited(
            "[[toolchain.node.inputs]]\npath = \".node-version\"",
            "[toolchain.node.component.extra]\nversion = \"1\"\n\
             [[toolchain.node.inputs]]\npath = \".node-version\"",
        );
        assert_eq!(
            refusal(&unlisted),
            "tog-toolchain.toml [node]: table for unlisted component extra"
        );
        assert_eq!(
            refusal(&cut_from("[[toolchain.node.inputs]]")),
            "tog-toolchain.toml [node]: no inputs"
        );
        assert_eq!(
            refusal(&cut_from("[toolchain.node.platforms.")),
            "tog-toolchain.toml [node]: no platforms"
        );
    }

    #[test]
    fn helper_pins_must_name_another_ecosystem_with_a_release() {
        let with = |helpers: &str| {
            edited(
                "revision = 1\n",
                &format!("revision = 1\nhelpers = {helpers}\n"),
            )
        };
        assert_eq!(
            refusal(&with("{ node = \"node-24.20.0-r1\" }")),
            "tog-toolchain.toml [node]: helper name \"node\" is not another ecosystem"
        );
        assert_eq!(
            refusal(&with("{ \"python 3\" = \"x\" }")),
            "tog-toolchain.toml [node]: helper name \"python 3\" is not another ecosystem"
        );
        assert_eq!(
            refusal(&with("{ python = \"\" }")),
            "tog-toolchain.toml [node]: helper python has an empty release"
        );
    }

    #[test]
    fn an_input_row_that_cannot_be_replayed_is_refused() {
        for (from, to, message) in [
            (
                "path = \".node-version\"",
                "path = \"\"",
                "input lacks a path or field",
            ),
            (
                "field = \"version\"",
                "field = \"\"",
                "input lacks a path or field",
            ),
            (
                "sha256 = \"5b9d0e73029969ae9000117cb877f17bb9841c1279bfe8024e294acfcf017800\"",
                "sha256 = \"5b9d0e73\"",
                "input .node-version has a bad sha256",
            ),
            (
                "sha256 = \"5b9d0e73029969ae9000117cb877f17bb9841c1279bfe8024e294acfcf017800\"",
                "sha256 = \"zz9d0e73029969ae9000117cb877f17bb9841c1279bfe8024e294acfcf017800\"",
                "input .node-version has a bad sha256",
            ),
            (
                "absent = true\n",
                "",
                "input package.json has neither a value nor absent = true",
            ),
        ] {
            assert_eq!(
                refusal(&edited(from, to)),
                format!("tog-toolchain.toml [node]: {message}"),
                "{from} -> {to}"
            );
        }
    }

    #[test]
    fn a_platform_row_that_cannot_be_fetched_is_refused() {
        let darwin = "[toolchain.node.platforms.\"aarch64-apple-darwin\".artifacts.node]";
        for (from, to, message) in [
            (
                darwin,
                "[toolchain.node.platforms.\"riscv64-unknown-linux-gnu\".artifacts.node]",
                "unsupported platform triple \"riscv64-unknown-linux-gnu\"",
            ),
            (
                "artifacts.node]\nprovider = \"nodejs.org\"\nbuild = \"24.20.0\"\nrecipe = \"nodejs/legacy\"\nurl = \"https://nodejs.org/dist/v24.20.0/node-v24.20.0-darwin-arm64.tar.gz\"",
                "artifacts.node]\nprovider = \"\"\nbuild = \"24.20.0\"\nrecipe = \"nodejs/legacy\"\nurl = \"https://nodejs.org/dist/v24.20.0/node-v24.20.0-darwin-arm64.tar.gz\"",
                "artifact row aarch64-apple-darwin/node lacks provider, build, recipe or url",
            ),
            (
                "artifacts.node]\nprovider = \"nodejs.org\"\nbuild = \"24.20.0\"\nrecipe = \"nodejs/legacy\"\nurl = \"https://nodejs.org/dist/v24.20.0/node-v24.20.0-darwin-arm64.tar.gz\"",
                "artifacts.node]\nprovider = \"nodejs.org\"\nbuild = \"\"\nrecipe = \"nodejs/legacy\"\nurl = \"https://nodejs.org/dist/v24.20.0/node-v24.20.0-darwin-arm64.tar.gz\"",
                "artifact row aarch64-apple-darwin/node lacks provider, build, recipe or url",
            ),
            (
                "artifacts.node]\nprovider = \"nodejs.org\"\nbuild = \"24.20.0\"\nrecipe = \"nodejs/legacy\"\nurl = \"https://nodejs.org/dist/v24.20.0/node-v24.20.0-darwin-arm64.tar.gz\"",
                "artifacts.node]\nprovider = \"nodejs.org\"\nbuild = \"24.20.0\"\nrecipe = \"\"\nurl = \"https://nodejs.org/dist/v24.20.0/node-v24.20.0-darwin-arm64.tar.gz\"",
                "artifact row aarch64-apple-darwin/node lacks provider, build, recipe or url",
            ),
            (
                "url = \"https://nodejs.org/dist/v24.20.0/node-v24.20.0-darwin-arm64.tar.gz\"",
                "url = \"\"",
                "artifact row aarch64-apple-darwin/node lacks provider, build, recipe or url",
            ),
            (
                "digest = \"sha256:40e5607e5ecb3db9192723776da2d75d966260fc74a7a9e731c1bd67dda96bc8\"",
                "digest = \"sha256:40e5607e\"",
                "artifact row aarch64-apple-darwin/node has a bad digest",
            ),
            (
                "digest = \"sha256:40e5607e5ecb3db9192723776da2d75d966260fc74a7a9e731c1bd67dda96bc8\"",
                "digest = \"md5:40e5607e5ecb3db9192723776da2d75d966260fc74a7a9e731c1bd67dda96bc8\"",
                "artifact row aarch64-apple-darwin/node has a bad digest",
            ),
        ] {
            assert_eq!(
                refusal(&edited(from, to)),
                format!("tog-toolchain.toml [node]: {message}"),
                "{from} -> {to}"
            );
        }
        // A platform table with no rows at all.
        let cut = NODE_LOCK.find(darwin).unwrap();
        let rest = NODE_LOCK[cut..]
            .find("[toolchain.node.platforms.\"x86_64")
            .unwrap();
        let empty = format!(
            "{}[toolchain.node.platforms.\"aarch64-apple-darwin\"]\nartifacts = {{}}\n{}",
            &NODE_LOCK[..cut],
            &NODE_LOCK[cut + rest..]
        );
        assert_eq!(
            refusal(&empty),
            "tog-toolchain.toml [node]: platform aarch64-apple-darwin has no artifacts"
        );
    }

    #[test]
    fn a_row_source_and_its_url_must_agree() {
        let https = "url = \"https://nodejs.org/dist/v24.20.0/node-v24.20.0-darwin-arm64.tar.gz\"";
        assert_eq!(
            refusal(&edited(https, &format!("{https}\nsource = \"mirror\""))),
            format!(
                "tog-toolchain.toml [node]: artifact row aarch64-apple-darwin/node has source \
                 \"mirror\"; the only source a row names is {PATH_SOURCE:?}"
            )
        );
        let disagree = format!(
            "tog-toolchain.toml [node]: artifact row aarch64-apple-darwin/node: \
             source = {PATH_SOURCE:?} goes with a file:// url and only with one"
        );
        assert_eq!(
            refusal(&edited(
                https,
                &format!("{https}\nsource = {PATH_SOURCE:?}")
            )),
            disagree
        );
        assert_eq!(
            refusal(&edited(https, "url = \"file:///opt/node\"")),
            disagree
        );
    }

    #[test]
    fn an_edited_row_under_the_old_id_is_refused_last() {
        // Every structural check passes; only the id disagrees.
        let text = edited(
            "digest = \"sha256:40e5607e5ecb3db9192723776da2d75d966260fc74a7a9e731c1bd67dda96bc8\"",
            "digest = \"sha256:0000000000000000000000000000000000000000000000000000000000000000\"",
        );
        // The computed id is the section id of the edited rows, pinned
        // here so the message is checked whole.
        assert_eq!(
            refusal(&text),
            "tog-toolchain.toml [node]: bundle_id \
             sha256:683bc7a0c5d38d3fcc9e73a6e55ab75bda308fb66204c4808942e750b5c1266b \
             does not match its rows and helper pins (sha256:5419c27039c163698f07224f3b288589eae2e2f35d950b911fc081350d54e895); the file was \
             edited, run `tog update --toolchain node`"
        );
    }

    #[test]
    fn a_revision_past_u32_is_refused() {
        assert_eq!(
            refusal(&edited("revision = 1", "revision = 4294967296")),
            "tog-toolchain.toml [node-24.20.0-r1]: revision 4294967296 is out of range"
        );
    }

    #[test]
    fn control_the_design_example_parses() {
        let lock = ToolchainLock::parse(NODE_LOCK.as_bytes()).unwrap();
        assert_eq!(lock.ecosystems(), ["node"]);
    }
}

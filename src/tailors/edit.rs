//! What `tog add`, `remove` and `update` ask of a tailor
//! (`Tailor::edit_manifest`), and the pieces every tailor's edit shares.
//!
//! Doctrine: resolution belongs to the ecosystem's pinned tool, realization
//! belongs to tog. Every manifest or lock edit is delegated to a store tool
//! (uv, the store node's npm, pinned pnpm, cargo, go, bundler, mix) through
//! the resolution door, the same trust boundary as missing-lock generation.
//! Where no pinned tool can make the edit, the tailor **refuses with the
//! exact line and file**; that is still one tool telling the user what to
//! type next. Tog edits a file itself in exactly one case: a plain
//! requirements file, where the "tool" is a text append.

use crate::kernel::resolve::{DelegateSpec, ResolutionDoor};
use crate::kernel::toolchain::Selected;
use crate::kernel::ui;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Which dependency edit the user asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EditVerb {
    Add,
    Remove,
    Update,
}

impl EditVerb {
    /// The verb as the user and most tools spell it.
    pub fn command(self) -> &'static str {
        match self {
            EditVerb::Add => "add",
            EditVerb::Remove => "remove",
            EditVerb::Update => "update",
        }
    }

    /// The verb in the line that reports the edit.
    pub fn past(self) -> &'static str {
        match self {
            EditVerb::Add => "added",
            EditVerb::Remove => "removed",
            EditVerb::Update => "updated",
        }
    }
}

/// One requested package, already validated by the command: the text the
/// tool receives (`requests>=2`) and the bare name (`requests`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DepSpec {
    pub name: String,
    pub text: String,
}

/// One ecosystem's share of a dependency edit.
pub struct ManifestEdit<'a> {
    pub verb: EditVerb,
    /// The project the edit is made in (the nearest project from the
    /// working directory upward).
    pub project: &'a Path,
    /// Empty only for an `update` of everything.
    pub specs: &'a [DepSpec],
    pub dev: bool,
    /// What the command lends the edit: the project's toolchain and the
    /// shared `tog x` tool cache.
    pub host: &'a dyn EditHost,
}

impl ManifestEdit<'_> {
    /// The specs as the tool receives them.
    pub fn texts(&self) -> Vec<String> {
        self.specs.iter().map(|spec| spec.text.clone()).collect()
    }

    /// The bare package names.
    pub fn names(&self) -> Vec<String> {
        self.specs.iter().map(|spec| spec.name.clone()).collect()
    }
}

/// What an edit changed, and where the sync after it runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EditOutcome {
    /// What the user is told changed.
    pub files: Vec<String>,
    /// Where the following sync runs: the project, or the pnpm workspace
    /// root whose lock the edit wrote.
    pub sync_root: PathBuf,
}

/// What a tailor's edit needs from the command that runs it. The command
/// owns toolchain selection outside a sync and the `~/.tog/x` cache; a
/// tailor reaches both only through this.
pub trait EditHost {
    /// The toolchain the project at `dir` selects for `ecosystem` (a tailor
    /// id), read as every command outside `sync` reads it. An edit asks for
    /// it only once it knows it will run a tool, so a refusal never waits
    /// on (or fails in) toolchain selection.
    fn toolchain(&self, dir: &Path, ecosystem: &str) -> io::Result<Selected>;

    /// Realize `package@version` from `ecosystem`'s registry tool into the
    /// `~/.tog/x` environment `tog x` would use for it from `project`, so
    /// the two share one environment. The resolver runs through `door`.
    fn cached_tool(
        &self,
        ecosystem: &str,
        project: &Path,
        package: &str,
        version: &str,
        door: &mut ResolutionDoor<'_>,
    ) -> io::Result<CachedTool>;
}

/// A registry tool realized in the `tog x` cache for an edit.
pub struct CachedTool {
    /// The cache root the tool is projected into.
    pub root: PathBuf,
    /// The root's shared lifecycle lock. `tog x --clean` removes a root
    /// under the exclusive lock, so the caller holds this for as long as it
    /// uses the root. Held, never read: dropping it releases the lock.
    #[allow(dead_code)]
    pub lock: fs::File,
    /// Whether this call realized it (a cache hit realizes nothing).
    pub realized: bool,
}

/// How `tog add` names an ecosystem's public registry: the `prefix:` that
/// says which ecosystem a spec is for, and the registry's name in messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PackageRegistry {
    pub prefix: &'static str,
    pub name: &'static str,
}

pub(crate) fn other(message: impl Into<String>) -> io::Error {
    io::Error::other(message.into())
}

/// Run an edit's tool with the user watching, through `door`; a failure
/// says nothing was synced.
pub(crate) fn run_inherited(
    door: &mut ResolutionDoor<'_>,
    spec: DelegateSpec,
    what: &str,
) -> io::Result<()> {
    spec.trace();
    let status = door
        .run(spec)
        .map_err(|error| io::Error::new(error.kind(), format!("run {what}: {error}")))?
        .status;
    if !status.success() {
        return Err(other(format!(
            "{what} failed (exit status {status}); nothing was synced"
        )));
    }
    Ok(())
}

/// `Tailor::registry_exists` over a registry's JSON API: `Some(latest
/// version)` when `url` answers, `None` on 404, and `Some("?")` when it
/// answers without a version `extract` can read.
pub(crate) fn registry_latest(
    registry: PackageRegistry,
    name: &str,
    url: &str,
    extract: fn(&serde_json::Value) -> Option<String>,
) -> io::Result<Option<String>> {
    ui::trace(&format!("asking {} about '{name}': {url}", registry.name));
    let value = get_json(url).map_err(|error| {
        other(format!(
            "could not ask {} whether '{name}' exists ({error}); say which ecosystem: {}:{name}",
            registry.name, registry.prefix
        ))
    })?;
    Ok(value.and_then(|value| extract(&value).or_else(|| Some("?".to_string()))))
}

fn get_json(url: &str) -> io::Result<Option<serde_json::Value>> {
    let agent = ureq::AgentBuilder::new()
        .https_only(true)
        .timeout(std::time::Duration::from_secs(20))
        .user_agent("tog (https://github.com/DigitalWestern/tog)")
        .build();
    match agent.get(url).call() {
        Ok(response) => {
            let text = response.into_string()?;
            serde_json::from_str(&text)
                .map(Some)
                .map_err(|error| other(format!("GET {url}: not JSON: {error}")))
        }
        Err(ureq::Error::Status(404, _)) => Ok(None),
        Err(ureq::Error::Status(code, _)) => Err(other(format!("GET {url}: HTTP {code}"))),
        Err(error) => Err(other(format!("GET {url}: {error}"))),
    }
}

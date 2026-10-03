//! The tailors: one folder per ecosystem adapter. Each tailor is a leaf of
//! the module graph: it depends on the kernel and the comforter, never on
//! another tailor or on a command.
//!
//! `Tailor` is the one blueprint every ecosystem implements and
//! `registry()` lists the ecosystems in the crate. Most commands
//! iterate the registry; some commands name an ecosystem directly
//! (for example `by_id`). Adding an ecosystem
//! is a folder plus one line in `REGISTRY` (docs/human/ADDING-A-TAILOR.md).

pub mod cargo;
pub mod dotnet;
pub mod edit;
pub mod elixir;
pub mod go;
pub mod node;
pub mod python;
pub mod ruby;

use crate::comforter::status::State;
use crate::kernel::context::Context;
use crate::kernel::fsroot::ProjectRoot;
use crate::kernel::objmeta::KindAdapter;
use crate::kernel::platform::Platform;
use crate::kernel::resolve::ResolutionDoor;
use crate::kernel::toolchain::{Catalog, LegacyEvidence, Selected};
use serde_json::Value;
use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

pub use edit::{
    CachedTool, DepSpec, EditHost, EditOutcome, EditVerb, ManifestEdit, PackageRegistry,
};

/// One row of `tog ls`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageRow {
    pub name: String,
    pub version: String,
    /// Artifact file, lockfile path, or content hash: shown under -v.
    pub detail: String,
}

/// What a closure lists: its toolchain versions and its packages.
#[derive(Debug, Clone, Default)]
pub struct ClosureListing {
    pub toolchain: Vec<(String, String)>,
    pub packages: Vec<PackageRow>,
}

/// What a sync asks of one tailor: the flags that change how it works
/// and the toolchain it must use. With `frozen` the caller skips `prepare`
/// and each tailor validates the committed lock instead of writing inputs.
pub struct SyncRequest<'a> {
    pub fresh: bool,
    pub frozen: bool,
    pub toolchain: &'a Selected,
    /// Every selection the project resolved, keyed by lock ecosystem. A
    /// tailor that builds with another ecosystem's toolchain (node-gyp's
    /// Python, an sdist's Rust) reads it through [`SyncRequest::helper`].
    pub selections: &'a BTreeMap<String, Selected>,
}

impl SyncRequest<'_> {
    /// The project's own selection for a helper ecosystem (`python`,
    /// `rust`), when its toolchain lock names one. `None` means the project
    /// has no such section, and the caller uses the shipped default.
    pub fn helper(&self, lock_ecosystem: &str) -> Option<&Selected> {
        self.selections.get(lock_ecosystem)
    }

    /// Every helper `tailor` builds with, decided as [`helper_selections`]
    /// decides them from this sync's selections.
    pub fn helpers(&self, tailor: &dyn Tailor) -> io::Result<BTreeMap<String, Selected>> {
        helper_selections(tailor, self.selections)
    }
}

/// The helper toolchains `tailor` builds with (`Tailor::helpers`), given the
/// selections a project resolved for its detected ecosystems: the project's
/// own selection for a helper ecosystem it has, the tailor's
/// `default_helper` otherwise. A helper with neither is absent, which means
/// the build decides per artifact (an sdist's own toolchain file).
///
/// `sync`, `status` and `tog x` all decide helpers through this rule, so a
/// status line predicts what the next sync would build on.
pub fn helper_selections(
    tailor: &dyn Tailor,
    selections: &BTreeMap<String, Selected>,
) -> io::Result<BTreeMap<String, Selected>> {
    let mut helpers = BTreeMap::new();
    for helper in tailor.helpers() {
        let selected = match selections.get(*helper) {
            Some(selected) => Some(selected.clone()),
            None => tailor.default_helper(helper)?,
        };
        if let Some(selected) = selected {
            helpers.insert((*helper).to_string(), selected);
        }
    }
    Ok(helpers)
}

/// The closure record of a helper decision: one entry per helper `tailor`
/// declares, the bundle id it built with or `null` when it had none to
/// record. `status` compares it against the decision a sync would make now.
pub fn helper_record(
    tailor: &dyn Tailor,
    helpers: &BTreeMap<String, Selected>,
) -> serde_json::Value {
    let mut record = serde_json::Map::new();
    for helper in tailor.helpers() {
        record.insert(
            (*helper).to_string(),
            helpers
                .get(*helper)
                .map_or(serde_json::Value::Null, |selected| {
                    serde_json::Value::String(selected.bundle_id())
                }),
        );
    }
    serde_json::Value::Object(record)
}

/// One `tog doctor` line contributed by a tailor.
#[derive(Debug, Clone)]
pub struct DoctorCheck {
    pub name: &'static str,
    pub ok: bool,
    pub detail: String,
}

fn unsupported(id: &str, verb: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        format!("tog {verb} does not support {id}"),
    )
}

/// The refusal a plan returns when the dependency lock it reads is absent.
/// `prepare` is the one method that generates a lock, and the command
/// layer skips it under `--frozen`, so an absent lock at planning time is
/// that promise being kept: nothing is generated, and the message names
/// the file and the way out.
pub(crate) fn missing_lock(project: &ProjectRoot, lock: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::NotFound,
        format!(
            "{} is missing and --frozen never creates it; run `tog` once without \
             --frozen and commit the file",
            project.path().join(lock).display()
        ),
    )
}

/// The verbs every ecosystem answers. Methods with a default body are the
/// optional ones: not every ecosystem builds, contributes run-time
/// environment, or has doctor checks.
///
/// Every method takes the project directory explicitly: a tailor never reads
/// the current directory itself, so the same tailor can serve `sync` in
/// `dir` and `build` in a workspace root above it.
///
/// The methods a sync calls (`detect` through `sync`) take the project as a
/// held directory descriptor (`ProjectRoot`), not a path: the command opens
/// it once, and every project read and write goes through it, so a project
/// directory renamed or replaced mid-sync cannot hand a tailor another
/// project's manifests. `project.path()` is for messages, for recording,
/// and for a child process's working directory; a tailor never reads the
/// project through it.
pub trait Tailor: Sync {
    /// The ecosystem name: closure file stem, `ls` vocabulary, plan JSON.
    fn id(&self) -> &'static str;

    /// The `[toolchain.<name>]` section key and the name toolchain input
    /// discovery knows this ecosystem by. Only the Rust tailor differs from
    /// its own id, because it is named after its package manager.
    fn lock_ecosystem(&self) -> &'static str {
        self.id()
    }

    /// Does this tailor own the closure file `.tog/closures/<name>.json`?
    /// A tailor that writes a second closure kind (cargo's `rustfmt`)
    /// overrides this.
    fn owns_closure(&self, name: &str) -> bool {
        name == self.id()
    }

    /// Are this ecosystem's inputs present in the project directory itself?
    /// The one test `sync`, `plan`, `status`, `deps`, and `fmt` all use.
    fn detect(&self, project: &ProjectRoot) -> io::Result<bool>;

    /// Before any store-touching work, for every detected ecosystem
    /// whatever the command is about: are the declarative toolchain inputs
    /// well-formed? Host-independent, so a malformed request refuses on
    /// every machine and every command, including a build of another
    /// ecosystem, rather than being read as no request. Most ecosystems'
    /// inputs are checked by the lock's own readers and need nothing here.
    fn check_inputs(&self, _project: &ProjectRoot) -> io::Result<()> {
        Ok(())
    }

    /// Before any store-touching work, for the ecosystems the command will
    /// realize: can this host run this ecosystem, and does this tog pin a
    /// toolchain for it here? Runs after `check_inputs`, so it may assume
    /// well-formed inputs.
    fn preflight(&self, platform: Platform, project: &ProjectRoot) -> io::Result<()>;

    /// Host-side preparation that must precede planning for one ecosystem:
    /// missing-lock generation with the ecosystem's own tool, the one place
    /// a tailor writes project inputs. Runs for detected ecosystems only,
    /// before that ecosystem plans, and never under `--frozen`; a plan that
    /// then finds no lock refuses with [`missing_lock`].
    ///
    /// The tool runs only through `door`, a missing-lock door on the
    /// ecosystem's own scope.
    fn prepare(
        &self,
        _ctx: &Context,
        _project: &ProjectRoot,
        _toolchain: &Selected,
        _door: &mut ResolutionDoor<'_>,
    ) -> io::Result<()> {
        Ok(())
    }

    /// `tog plan`: the plan as pretty-printed JSON text, without
    /// realizing anything. `None` when, after `prepare`, there is nothing of
    /// this ecosystem to plan (the text is produced here, not a `Value`, so
    /// each plan's key order stays exactly what its producer serializes).
    /// A planner that asks the ecosystem's tool (a consistency gate, a lock
    /// parser) runs it through `door`, a planner door.
    fn plan(
        &self,
        ctx: &Context,
        project: &ProjectRoot,
        toolchain: &Selected,
        door: &mut ResolutionDoor<'_>,
    ) -> io::Result<Option<String>>;

    /// A sync: plan, realize, project, and narrate with
    /// `ui::synced`. Returns whether anything was synced.
    fn sync(
        &self,
        ctx: &Context,
        project: &ProjectRoot,
        request: &SyncRequest,
        attribution: &mut crate::kernel::policy::Attribution,
    ) -> io::Result<bool>;

    /// Can `tog build <id>` name this ecosystem at all?
    fn builds(&self) -> bool {
        false
    }

    /// `tog build` inference: is there something of this ecosystem to
    /// build from `cwd`? (Ancestor search where the ecosystem supports it.)
    fn build_present(&self, _cwd: &Path) -> io::Result<bool> {
        Ok(false)
    }

    /// The directory `tog build` roots at for this ecosystem from `cwd`.
    fn build_root(&self, _cwd: &Path) -> io::Result<PathBuf> {
        Err(unsupported(self.id(), "build"))
    }

    /// Plan, realize, project, then run the sandboxed build in `root`.
    fn build(
        &self,
        _ctx: &Context,
        _root: &Path,
        _cwd: &Path,
        _args: &[String],
        _toolchain: &Selected,
        _attribution: &mut crate::kernel::policy::Attribution,
    ) -> io::Result<()> {
        Err(unsupported(self.id(), "build"))
    }

    /// `tog run`: the PATH prefixes and environment this ecosystem's
    /// projection under `dir` contributes to `command`. `cwd` is where the
    /// user ran from (a workspace subdirectory); `cmd` is the command line,
    /// for ecosystems that refuse some commands.
    fn run_env(
        &self,
        _ctx: &Context,
        _dir: &Path,
        _cwd: &Path,
        _cmd: &[String],
        _command: &mut Command,
    ) -> io::Result<Vec<String>> {
        Ok(Vec::new())
    }

    /// `tog run`: why `cmd` is refused before any environment is looked
    /// up, when it is one of this ecosystem's package-manager verbs that
    /// would write into a projection (`pip install`, `npm install`). The
    /// refusal is the same in every project, so it needs no projection.
    fn refused_command(&self, _cmd: &[String]) -> Option<String> {
        None
    }

    /// `tog run`: why a package.json script may not run in `dir`, when this
    /// ecosystem's projection there forbids running project code outside
    /// the sandbox (.NET: MSBuild belongs in `tog build`).
    fn refused_package_script(&self, _dir: &Path) -> Option<String> {
        None
    }

    /// `tog ls`: what a closure of this ecosystem lists.
    fn listing(&self, ecosystem: &str, body: &Value) -> ClosureListing;

    /// `tog status`: is the closure's projection still current?
    fn closure_state(
        &self,
        platform: Platform,
        dir: &Path,
        ecosystem: &str,
        body: &Value,
    ) -> io::Result<State>;

    /// `tog doctor`: project-level checks specific to this ecosystem.
    fn doctor(&self, _platform: Platform, _dir: &Path) -> Vec<DoctorCheck> {
        Vec::new()
    }

    /// `tog sbom`: CycloneDX components for a closure of this ecosystem.
    fn sbom_components(
        &self,
        ecosystem: &str,
        body: &Value,
        out: &mut Vec<Value>,
    ) -> io::Result<()>;

    /// The store object kinds this tailor produces: their live and
    /// legacy-migration identity grammars plus metadata adapters (`objmeta`).
    /// Every kind a tailor commits must have a row here or GC refuses to
    /// certify its records.
    fn object_kinds(&self) -> &'static [KindAdapter] {
        &[]
    }

    /// The object kinds among `object_kinds` that are this ecosystem's
    /// realized toolchain (`cpython`, `nodejs`, ...), which `tog doctor`
    /// lists from the store's metadata.
    fn toolchain_kinds(&self) -> &'static [&'static str] {
        &[]
    }

    /// The shipped toolchain catalog: this ecosystem's pin tables as release
    /// bundles (`kernel::toolchain`), the rows a toolchain lock is minted
    /// from. Selection and legacy seeding read it; realization keeps reading
    /// the pin tables, so no object identity changes.
    fn toolchain_catalog(&self) -> io::Result<Catalog>;

    /// The reader of a toolchain that is not a catalog release at all: a
    /// directory on this machine (`kernel::toolchain::PATH_SOURCE`), which
    /// the lock then records in place of a catalog selection. The command
    /// layer hands it to resolution on `EcosystemInput::external`. `None`
    /// means the catalog always answers, as it does for every ecosystem
    /// that has no such thing.
    fn external_toolchain(&self) -> Option<crate::comforter::toolchain::ExternalToolchain> {
        None
    }

    /// The helper releases a lock section written now pins, by helper lock
    /// ecosystem (see [`Tailor::helpers`]): what a build that needs a
    /// helper the project does not lock uses by default, fixed when the
    /// section is written so a later catalog does not move it.
    fn helper_pins(&self) -> io::Result<BTreeMap<String, String>> {
        Ok(BTreeMap::new())
    }

    /// The helper releases this ecosystem's builds used before lock
    /// sections pinned them: what a section with no pin keeps.
    fn legacy_helper_pins(&self) -> BTreeMap<String, String> {
        BTreeMap::new()
    }

    /// What a closure of this ecosystem written before the toolchain lock
    /// proves about its toolchain (`kernel::toolchain::seed`): `platform`
    /// is the closure envelope's platform, `body` the closure body
    /// `read_closure` returns, from which the exact recorded versions come.
    /// `store` is the active store, opened read-only: the runtime object the
    /// body names proves the artifacts it was built from only when that
    /// store holds it (`comforter::toolchain::prove_legacy_runtime`).
    fn legacy_toolchain_evidence(
        &self,
        ecosystem: &str,
        platform: Option<Platform>,
        body: &Value,
        store: Option<&crate::kernel::store::Store>,
    ) -> LegacyEvidence;

    /// The `--eco` word `tog fmt` accepts for this ecosystem, when it
    /// has a pinned formatter.
    fn fmt_ecosystem(&self) -> Option<&'static str> {
        None
    }

    /// `tog fmt`, before the store is opened: refuse a host with no
    /// pinned formatter component.
    fn fmt_preflight(&self, _platform: Platform) -> io::Result<()> {
        Err(unsupported(self.id(), "fmt"))
    }

    /// `tog fmt`, before the store is opened: is there a project of this
    /// ecosystem to format from `cwd`?
    fn fmt_check_project(&self, _cwd: &Path) -> io::Result<()> {
        Err(unsupported(self.id(), "fmt"))
    }

    /// `tog fmt`: the root of the workspace `cwd` belongs to, found with
    /// the toolchain `toolchain` names. The formatter's record is written
    /// there and judged against the lock there, so `tog fmt` takes its
    /// toolchain from that directory's lock when it has one.
    fn fmt_root(&self, _ctx: &Context, cwd: &Path, _toolchain: &Selected) -> io::Result<PathBuf> {
        cwd.canonicalize()
    }

    /// `tog fmt`: realize the formatter, record its closure, and run it
    /// sandboxed over the workspace `cwd` belongs to.
    fn fmt(
        &self,
        _ctx: &Context,
        _cwd: &Path,
        _check: bool,
        _args: &[String],
        _toolchain: &Selected,
        _attribution: &mut crate::kernel::policy::Attribution,
    ) -> io::Result<i32> {
        Err(unsupported(self.id(), "fmt"))
    }

    /// `tog add`: the ecosystem's public package registry, the `prefix:`
    /// that names it on the command line, and its name in messages. `None`
    /// for an ecosystem `add` cannot choose.
    fn package_registry(&self) -> Option<PackageRegistry> {
        None
    }

    /// Whether a package name's shape alone says it belongs here
    /// (`@scope/name` is npm's), so `tog add` needs no lookup to choose.
    fn claims_package_name(&self, _name: &str) -> bool {
        false
    }

    /// Whether this ecosystem's public registry knows `name`: `Some(latest
    /// version)` when it does, `None` when it does not.
    fn registry_exists(&self, _name: &str) -> io::Result<Option<String>> {
        Err(unsupported(self.id(), "add"))
    }

    /// Where the sync after a dependency edit made in `project` runs: the
    /// project itself, or the root whose lock the edit writes.
    fn edit_root(&self, project: &Path) -> io::Result<PathBuf> {
        Ok(project.to_path_buf())
    }

    /// `tog add` / `remove` / `update` for this ecosystem: edit the manifest
    /// and lock with the ecosystem's pinned tool, run through `door`. A
    /// tailor that cannot make an edit refuses with the exact command to
    /// run; the default refuses.
    fn edit_manifest(
        &self,
        _ctx: &Context,
        _edit: &ManifestEdit<'_>,
        _door: &mut ResolutionDoor<'_>,
    ) -> io::Result<EditOutcome> {
        Err(unsupported(self.id(), "add, remove, and update"))
    }

    /// `tog x`: how this ecosystem runs a tool straight from its public
    /// registry, when it can.
    fn registry_tool(&self) -> io::Result<&'static dyn RegistryTool> {
        Err(unsupported(self.id(), "x"))
    }

    /// The other ecosystems whose toolchains this tailor's builds run on,
    /// by lock ecosystem: node-gyp's `python`, an sdist's `rust`. The
    /// decision is recorded in the closure and is part of what `status`
    /// compares, so a project that stops (or starts) locking a helper is
    /// out of step until it syncs.
    fn helpers(&self) -> &'static [&'static str] {
        &[]
    }

    /// The selection a helper gets when the project does not select one.
    /// `None` means there is no single default: the build decides per
    /// artifact.
    fn default_helper(&self, _helper: &str) -> io::Result<Option<Selected>> {
        Ok(None)
    }

    /// The files a resolution door of this ecosystem produces in
    /// `project` (its lock and manifest), relative to the project. A
    /// non-empty list declares a resolvable lock: every closure of this
    /// ecosystem then needs an attesting resolution record, or records
    /// `unrecorded-resolution`. Empty means no join at all.
    fn resolution_outputs(&self, _project: &ProjectRoot) -> io::Result<Vec<PathBuf>> {
        Ok(Vec::new())
    }

    /// The files a resolution door's tool reads in `project` but does not
    /// write (other workspace members' manifests, the tool's
    /// configuration), relative to the project. A record must name each one
    /// that exists, by digest.
    fn resolution_inputs(&self, _project: &ProjectRoot) -> io::Result<Vec<PathBuf>> {
        Ok(Vec::new())
    }

    /// `tog attest`: run this ecosystem's lock check through `door` (an
    /// attest door) in `project`. A check that leaves the lock and manifest
    /// byte-unchanged yields the signed record and its bytes; a check that
    /// fails or would change the lock is an error. Either way the check
    /// publishes nothing: `tog attest` publishes every ecosystem's record
    /// together (`record::publish_receipts`) only after all checks passed.
    fn attest_lock(
        &self,
        _ctx: &Context,
        _project: &ProjectRoot,
        _toolchain: &Selected,
        _door: &mut ResolutionDoor<'_>,
    ) -> io::Result<(crate::kernel::resolve::record::ResolutionRecord, Vec<u8>)> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "tog attest does not support {}: it has no lock check that runs through a \
                 resolution door",
                self.id()
            ),
        ))
    }
}

/// The resolution files `tailor` names in `project`, or `None` when it
/// declares no resolvable lock.
pub fn resolution_files(
    tailor: &dyn Tailor,
    project: &ProjectRoot,
) -> io::Result<Option<crate::kernel::resolve::record::ResolutionFiles>> {
    let outputs = tailor.resolution_outputs(project)?;
    if outputs.is_empty() {
        return Ok(None);
    }
    Ok(Some(crate::kernel::resolve::record::ResolutionFiles {
        outputs,
        inputs: tailor.resolution_inputs(project)?,
    }))
}

/// The record a door run of `tailor` leaves in `project`: the tailor's
/// resolution files, the process signing key (`None` writes it unsigned),
/// and the tool with the arguments it ran with. `tog attest`'s check sets
/// `require_unchanged` and clears `publish_receipt`.
pub fn record_spec(
    tailor: &dyn Tailor,
    project: &ProjectRoot,
    tool: crate::kernel::resolve::record::Tool,
    args: &[&str],
) -> io::Result<crate::kernel::resolve::record::RecordSpec> {
    let files = resolution_files(tailor, project)?.ok_or_else(|| {
        io::Error::other(format!(
            "{} declares no resolution outputs, so its door has no record to write",
            tailor.id()
        ))
    })?;
    let mut command = vec![tool.name.clone()];
    command.extend(args.iter().map(|arg| arg.to_string()));
    Ok(crate::kernel::resolve::record::RecordSpec {
        tool,
        command,
        files,
        key: crate::comforter::signing_key(),
        require_unchanged: false,
        publish_receipt: true,
    })
}

/// Hand the closure writer's resolution join every tailor's resolution
/// files, looked up by the closure's ecosystem. Only a closure named for a
/// tailor's own id joins: `rustfmt` is a Cargo closure with no lock of its
/// own. `commands::dispatch` calls this before a verb that can write a
/// project closure. Idempotent.
pub fn install_resolution_files() {
    crate::comforter::join::install_resolution_files(std::sync::Arc::new(
        |ecosystem: &str, project: &ProjectRoot| match by_id(ecosystem) {
            Some(tailor) => resolution_files(tailor, project),
            None => Ok(None),
        },
    ));
}

/// What `tog x` asks of an ecosystem that installs tools from a public
/// registry (`Tailor::registry_tool`). The command owns everything around
/// the tool: the `~/.tog/x` directory, its cache key, its lifecycle lock,
/// its gc root, and the cached-projection checks. The tool owns resolving
/// one package, realizing and projecting it into that directory, and the
/// environment a launched executable runs in.
pub trait RegistryTool: Sync {
    /// The first word of every `~/.tog/x` directory this tool's caches live
    /// in (`py`, `npm`). It is part of the cache directory name, so changing
    /// it orphans every existing cache.
    fn cache_prefix(&self) -> &'static str;

    /// The store object id of the runtime `toolchain` names, computed
    /// without touching the store. It is part of the cache key.
    fn runtime_object_id(&self, platform: Platform, toolchain: &Selected) -> io::Result<String>;

    /// The word that names this registry on the command line: the
    /// `py:`/`npm:` tool prefix and the `--py`/`--npm` flag.
    fn spelling(&self) -> &'static str;

    /// The registry's name in `tog x` messages (`PyPI`, `npm`).
    fn registry_name(&self) -> &'static str;

    /// The ecosystem's name for a project in `tog x` messages (`Python`,
    /// `Node`).
    fn project_label(&self) -> &'static str;

    /// Why `tog x` chose this registry from the project it runs in, for the
    /// trace line.
    fn detection_reason(&self) -> &'static str;

    /// Whether package names may carry a `scope/` segment (npm's
    /// `@scope/name`).
    fn scoped_packages(&self) -> bool {
        false
    }

    /// The directory under a cache `root` that holds the executables the
    /// installed package provides.
    fn bin_dir(&self, root: &Path) -> PathBuf;

    /// Does the projection in `root` still point at `env_path`, the
    /// canonical environment object its recorded `closure` names? `x`
    /// refuses to run a cached tool whose projection points elsewhere.
    fn projection_points_at(
        &self,
        store: &crate::kernel::store::Store,
        root: &Path,
        closure: &Value,
        env_path: &Path,
    ) -> io::Result<bool>;

    /// The packages a cache root written before `x` recorded its request
    /// was made for, read back from the manifest this tool generated in
    /// it. `None` when `root` holds no such manifest.
    fn legacy_packages(&self, root: &Path) -> Option<Vec<LegacyPackage>>;

    /// What `tog x --clean` adds to its summary when it removed at least
    /// one of this tool's environments.
    fn clean_note(&self) -> Option<&'static str> {
        None
    }

    /// The helper toolchains a realization builds with, a subset of the
    /// tailor's `helpers`. Each one's runtime object id is part of the
    /// cache key, and a tool with none keeps the `x/3` key.
    fn helpers(&self) -> &'static [&'static str] {
        &[]
    }

    /// The store object id of `helper`'s runtime as `selected` names it,
    /// computed without touching the store, for the cache key.
    fn helper_object_id(
        &self,
        _platform: Platform,
        helper: &str,
        _selected: &Selected,
    ) -> io::Result<String> {
        Err(io::Error::other(format!("no {helper} helper here")))
    }

    /// Resolve `package` (exactly `version`, or the registry's latest),
    /// realize it on `toolchain` and the `helpers` it builds with, and
    /// project it into `root`. The resolver runs through `door`, an `x`
    /// door whose scope the projection claims.
    fn realize(
        &self,
        door: &mut ResolutionDoor<'_>,
        root: &Path,
        package: &str,
        version: Option<&str>,
        toolchain: &Selected,
        helpers: &BTreeMap<String, Selected>,
    ) -> io::Result<()>;

    /// What an executable launched from a realized `root` runs with.
    fn launch_env(
        &self,
        store: &crate::kernel::store::Store,
        activity: &crate::kernel::activity::StoreActivity,
        platform: Platform,
        root: &Path,
        toolchain: &Selected,
    ) -> io::Result<ToolEnv>;
}

/// One package a pre-record `x` cache root was made for
/// (`RegistryTool::legacy_packages`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyPackage {
    pub package: String,
    pub version: Option<String>,
}

/// The environment a registry tool launches in (`RegistryTool::launch_env`).
#[derive(Debug, Clone, Default)]
pub struct ToolEnv {
    /// Directories placed ahead of the inherited PATH, in order.
    pub path: Vec<PathBuf>,
    /// Variables set on the child.
    pub vars: Vec<(&'static str, std::ffi::OsString)>,
}

/// Display order everywhere: `plan` output, `sync` narration, `status`
/// rows, `ls`. Adding an ecosystem is one line here.
static REGISTRY: [&dyn Tailor; 7] = [
    &python::tailor::Python,
    &node::tailor::Node,
    &cargo::tailor::Cargo,
    &go::tailor::Go,
    &ruby::tailor::Ruby,
    &elixir::tailor::Elixir,
    &dotnet::tailor::Dotnet,
];

pub fn registry() -> &'static [&'static dyn Tailor] {
    &REGISTRY
}

pub fn by_id(id: &str) -> Option<&'static dyn Tailor> {
    registry().iter().copied().find(|tailor| tailor.id() == id)
}

/// The tailor that wrote `.tog/closures/<name>.json`, if any.
pub fn for_closure(name: &str) -> Option<&'static dyn Tailor> {
    registry()
        .iter()
        .copied()
        .find(|tailor| tailor.owns_closure(name))
}

/// Every tailor's object-kind rows, in registry order.
pub fn kind_adapters() -> impl Iterator<Item = &'static KindAdapter> {
    registry()
        .iter()
        .flat_map(|tailor| tailor.object_kinds().iter())
}

/// Test-only view of the identities produced by every tailor's real identity
/// constructor. The kernel's live-grammar matrix uses these cases instead of
/// synthesizing an identity from the row it is supposed to check.
#[cfg(test)]
pub(crate) fn live_identity_cases(platform: Platform) -> Vec<crate::kernel::types::Identity> {
    let mut cases = Vec::new();
    cases.extend(cargo::live_identity_cases(platform));
    cases.extend(dotnet::live_identity_cases(platform));
    cases.extend(elixir::live_identity_cases(platform));
    cases.extend(go::live_identity_cases(platform));
    cases.extend(node::live_identity_cases(platform));
    cases.extend(python::live_identity_cases(platform));
    cases.extend(ruby::live_identity_cases(platform));
    cases
}

/// Hand the kernel every tailor's object-kind rows. `commands::dispatch`
/// calls this before any command runs, and public tailor realization entry
/// points call it before they can publish. Idempotent.
pub fn install_kinds() {
    crate::kernel::objmeta::install_kinds(kind_adapters());
}

/// The tailors whose inputs are present in `dir`, in registry order.
pub fn detected(dir: &Path) -> io::Result<Vec<&'static dyn Tailor>> {
    // A directory that is not there, or not a directory, has nothing to
    // detect. One tog may not read is an error naming the path: an empty
    // detection would report "no project here" for a project that exists.
    let project = match ProjectRoot::open(dir) {
        Ok(project) => project,
        Err(error)
            if error.kind() == io::ErrorKind::NotFound
                || error.kind() == io::ErrorKind::InvalidData =>
        {
            return Ok(Vec::new())
        }
        Err(error) => return Err(error),
    };
    detected_in(&project)
}

/// `detected` for a project the caller already holds: sync detects through
/// the descriptor it reads everything else through.
pub fn detected_in(project: &ProjectRoot) -> io::Result<Vec<&'static dyn Tailor>> {
    let mut found = Vec::new();
    for tailor in registry() {
        if tailor.detect(project)? {
            found.push(*tailor);
        }
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::toolchain::{qualified, seed, Request, SourcePolicy};
    use serde_json::json;

    const DARWIN: Platform = Platform::Aarch64AppleDarwin;
    const LINUX: Platform = Platform::X86_64UnknownLinuxGnu;

    /// A project with its manifest but no lock is refused by name and
    /// nothing is written: the lock is `prepare`'s to generate, and a
    /// frozen run skips `prepare`. One row per tailor that reads a lock.
    #[test]
    fn a_missing_lock_is_refused_by_name_and_nothing_is_written() {
        type RequireLock = fn(&ProjectRoot) -> io::Result<()>;
        let rows: [(&str, &str, &str, &str, RequireLock); 4] = [
            (
                "node",
                "package.json",
                "{\"name\": \"hello\"}\n",
                "package-lock.json",
                node::inputs::require_lock,
            ),
            (
                "ruby",
                "Gemfile",
                "source \"https://rubygems.org\"\n",
                "Gemfile.lock",
                ruby::require_lock,
            ),
            (
                "elixir",
                "mix.exs",
                "defmodule Hello.MixProject do\nend\n",
                "mix.lock",
                elixir::require_lock,
            ),
            (
                "dotnet",
                "hello.csproj",
                "<Project Sdk=\"Microsoft.NET.Sdk\"></Project>\n",
                "packages.lock.json",
                dotnet::require_lock,
            ),
        ];
        for (tailor, manifest, text, lock, require_lock) in rows {
            let temp = crate::kernel::testutil::TempDir::named(&format!("{tailor}-frozen"));
            std::fs::write(temp.0.join(manifest), text).unwrap();
            let project = ProjectRoot::open(&temp.0).unwrap();
            let Err(error) = require_lock(&project) else {
                panic!("{tailor}: a missing {lock} was accepted");
            };
            assert_eq!(error.kind(), io::ErrorKind::NotFound, "{tailor}");
            let message = error.to_string();
            assert!(
                message.contains(&format!("{lock} is missing and --frozen never creates it")),
                "{tailor}: {message}"
            );
            assert!(
                message.contains("run `tog` once without --frozen"),
                "{tailor}: {message}"
            );
            assert!(!temp.0.join(lock).exists(), "{tailor}");
            std::fs::write(temp.0.join(lock), "").unwrap();
            require_lock(&project).unwrap_or_else(|error| panic!("{tailor}: {error}"));
        }
    }

    #[test]
    fn detection_reports_an_unreadable_project_instead_of_finding_nothing() {
        use std::os::unix::fs::PermissionsExt as _;
        // SAFETY: geteuid has no preconditions.
        if unsafe { libc::geteuid() } == 0 {
            return; // root reads through any mode
        }
        let temp = crate::kernel::testutil::TempDir::new();
        let parent = temp.0.join("locked");
        let project = parent.join("project");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(project.join("go.mod"), "module example.com/m\n").unwrap();
        assert!(detected(&temp.0.join("absent")).unwrap().is_empty());
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o000)).unwrap();
        let result = detected(&project);
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o755)).unwrap();
        let error = match result {
            Ok(found) => panic!("an unreadable project detected {} tailors", found.len()),
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied, "{error}");
        assert!(
            error.to_string().contains(&project.display().to_string()),
            "{error}"
        );
    }

    #[test]
    fn every_tailor_ships_a_complete_catalog_under_the_shipped_source_policy() {
        let policy = SourcePolicy::shipped();
        let mut providers = std::collections::BTreeSet::new();
        for tailor in registry() {
            let catalog = tailor.toolchain_catalog().unwrap();
            assert_eq!(catalog.ecosystem(), tailor.id());
            assert!(!catalog.bundles().is_empty(), "{}", tailor.id());
            for bundle in catalog.bundles() {
                assert!(
                    bundle.complete_everywhere(),
                    "{}: release {} is incomplete",
                    tailor.id(),
                    bundle.release
                );
                for row in &bundle.artifacts {
                    let authorized =
                        policy
                            .authorize(&row.provider, &row.url)
                            .unwrap_or_else(|error| {
                                panic!("{}: {}: {error}", tailor.id(), bundle.release)
                            });
                    assert_eq!(authorized.publisher, row.provider);
                    providers.insert(row.provider.clone());
                    assert!(
                        row.recipe.contains('/'),
                        "{}: recipe {}",
                        tailor.id(),
                        row.recipe
                    );
                }
            }
            // The newest complete release is selectable, and the choice is
            // the same however many times it is made.
            let first = catalog.select(&Request::newest()).unwrap().bundle_id();
            let again = catalog.select(&Request::newest()).unwrap().bundle_id();
            assert_eq!(first, again);
        }
        // Every shipped publisher serves some tailor's rows: a catalog that
        // drops out of the registry leaves its publisher unused and fails here.
        let shipped: std::collections::BTreeSet<String> = policy
            .publishers()
            .iter()
            .map(|publisher| publisher.id.clone())
            .collect();
        assert_eq!(providers, shipped);
    }

    /// Every toolchain realization asks the source policy before it fetches:
    /// with each row pointed off its publisher's endpoints, every one is
    /// refused naming that URL, before the cache or the network is touched.
    #[test]
    fn every_toolchain_realization_checks_its_rows_against_the_source_policy() {
        use crate::kernel::activity::StoreActivity;
        use crate::kernel::store::Store;
        type Realize = fn(&Store, &StoreActivity, Platform, &Selected) -> io::Result<PathBuf>;
        fn rustfmt(
            store: &Store,
            activity: &StoreActivity,
            platform: Platform,
            selected: &Selected,
        ) -> io::Result<PathBuf> {
            // The formatter pairs with a Rust object that must exist.
            let rust = store.object_path(&crate::kernel::provider::rust::runtime_object_id(
                platform, selected,
            )?);
            std::fs::create_dir_all(&rust)?;
            crate::tailors::cargo::rustfmt::ensure_rustfmt(
                store, activity, platform, selected, &rust,
            )
        }
        fn rust_extras(
            store: &Store,
            activity: &StoreActivity,
            platform: Platform,
            selected: &Selected,
        ) -> io::Result<PathBuf> {
            let extras = crate::kernel::provider::rust_extras::Extras {
                components: vec!["clippy".into()],
                targets: Vec::new(),
                profile: None,
            };
            crate::kernel::provider::rust_extras::realize_toolchain(
                store, activity, platform, selected, &extras,
            )
        }
        let cases: [(&str, &str, Realize); 10] = [
            (
                "python",
                "cpython",
                crate::kernel::provider::cpython::realize_runtime,
            ),
            ("python", "uv", crate::kernel::provider::cpython::realize_uv),
            (
                "cargo",
                "rustc",
                crate::kernel::provider::rust::realize_runtime,
            ),
            ("cargo", "channel-manifest", rust_extras),
            ("cargo", "rustfmt", rustfmt),
            ("node", "node", crate::tailors::node::realize_runtime),
            ("go", "go", crate::tailors::go::realize_runtime),
            ("ruby", "ruby", crate::tailors::ruby::realize_runtime),
            ("elixir", "otp", crate::tailors::elixir::realize_runtime),
            (
                "dotnet",
                "dotnet-sdk",
                crate::tailors::dotnet::realize_runtime,
            ),
        ];
        let platform = Platform::host().unwrap();
        let temp = crate::kernel::testutil::TempDir::new();
        let store = scratch_store(&temp, "store");
        std::fs::create_dir_all(store.root.join("tmp")).unwrap();
        let activity = &store
            .activity(crate::kernel::activity::ActivityMode::Shared)
            .unwrap();
        for (tailor, component, realize) in cases {
            let catalog = by_id(tailor).unwrap().toolchain_catalog().unwrap();
            let mut selected = crate::kernel::toolchain::shipped(&catalog).unwrap();
            for row in &mut selected.bundle.artifacts {
                row.url = format!("https://elsewhere.example/{}", row.component);
            }
            let error = realize(&store, activity, platform, &selected)
                .err()
                .unwrap_or_else(|| panic!("{tailor} {component} realized off-policy"));
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied, "{error}");
            assert!(
                error.to_string().contains(&format!(
                    "source policy refuses https://elsewhere.example/{component} for "
                )),
                "{tailor} {component}: {error}"
            );
        }
    }

    /// Each shipped publisher's real redirect chain stays inside its own
    /// endpoints: one row of the default releases per publisher, on any
    /// platform, is opened through the policy-checked fetch and its first
    /// bytes read.
    #[test]
    #[ignore = "network: opens one shipped artifact per publisher"]
    fn every_publishers_real_redirects_stay_inside_the_shipped_policy() {
        use std::io::Read as _;
        let policy = SourcePolicy::shipped();
        let mut opened = std::collections::BTreeSet::new();
        for tailor in registry() {
            let catalog = tailor.toolchain_catalog().unwrap();
            let bundle = crate::kernel::toolchain::shipped(&catalog).unwrap().bundle;
            for row in &bundle.artifacts {
                if !opened.insert(row.provider.clone()) {
                    continue;
                }
                let (mut body, _) =
                    crate::kernel::fetch::open_authorized(&policy, &row.provider, &row.url)
                        .unwrap_or_else(|error| panic!("{}: {error}", row.provider));
                let mut first = [0u8; 16];
                body.read_exact(&mut first)
                    .unwrap_or_else(|error| panic!("{}: {error}", row.url));
            }
        }
        assert_eq!(opened.len(), policy.publishers().len());
    }

    #[test]
    fn shipped_rows_carry_the_verified_digests_with_their_algorithm() {
        let sha512_components = [
            ("dotnet", "dotnet-sdk"),
            ("elixir", "hex"),
            ("elixir", "rebar3"),
        ];
        let mut seen = 0;
        for tailor in registry() {
            let catalog = tailor.toolchain_catalog().unwrap();
            for bundle in catalog.bundles() {
                for row in &bundle.artifacts {
                    let want512 =
                        sha512_components.contains(&(tailor.id(), row.component.as_str()));
                    let spelled = qualified(&row.digest);
                    if want512 {
                        seen += 1;
                        assert!(
                            spelled.starts_with("sha512:"),
                            "{}: {spelled}",
                            row.component
                        );
                        assert_eq!(spelled.len(), "sha512:".len() + 128);
                    } else {
                        assert!(
                            spelled.starts_with("sha256:"),
                            "{}: {spelled}",
                            row.component
                        );
                        assert_eq!(spelled.len(), "sha256:".len() + 64);
                    }
                }
            }
        }
        // Two platforms each for every SDK, and for every pair's Hex and
        // rebar3.
        let sdks = by_id("dotnet").unwrap().toolchain_catalog().unwrap();
        let pairs = by_id("elixir").unwrap().toolchain_catalog().unwrap();
        assert_eq!(seen, 2 * sdks.bundles().len() + 4 * pairs.bundles().len());
        // Python: every CPython release, each with the one pinned uv.
        let python = by_id("python").unwrap().toolchain_catalog().unwrap();
        assert!(python.bundles().len() > 5);
        for bundle in python.bundles() {
            assert_eq!(bundle.components.len(), 2);
            assert_eq!(bundle.artifacts.len(), 4);
            assert!(bundle.artifact(LINUX, "uv").is_some());
        }
        // BEAM: the pair is primary, OTP first, and the Linux OTP row names
        // the relocation recipe the Linux identity already commits to.
        let elixir = by_id("elixir").unwrap().toolchain_catalog().unwrap();
        let beam = elixir.default_release().unwrap();
        assert_eq!(beam.primary, ["otp", "elixir"]);
        assert_eq!(
            beam.artifact(DARWIN, "otp").unwrap().recipe,
            "beam-toolchain/1"
        );
        assert_eq!(
            beam.artifact(LINUX, "otp").unwrap().recipe,
            "otp-install-cross-minimal/1"
        );
        assert_eq!(
            beam.artifact(DARWIN, "hex").unwrap().digest,
            beam.artifact(LINUX, "hex").unwrap().digest
        );
        // Rust: rustfmt rides in the same bundle under its own recipe, and
        // so does the channel manifest extras are provisioned from.
        let cargo = by_id("cargo").unwrap().toolchain_catalog().unwrap();
        let rust = cargo.default_release().unwrap();
        assert_eq!(rust.components.len(), 5);
        assert_eq!(rust.artifact(LINUX, "rustfmt").unwrap().recipe, "rustfmt/1");
        assert_eq!(
            rust.artifact(DARWIN, "channel-manifest").unwrap().digest,
            rust.artifact(LINUX, "channel-manifest").unwrap().digest
        );
        assert_eq!(
            rust.artifact(LINUX, "channel-manifest").unwrap().recipe,
            "rust-channel-manifest/1"
        );
        assert_eq!(
            rust.artifact(LINUX, "rustc").unwrap().recipe,
            "rust-toolchain/1"
        );
    }

    /// Each ecosystem's shipped default and its bundle id, as they were
    /// before the catalogs became generated data and grew: a newer release
    /// in a catalog must never move them (#187).
    const SHIPPED_DEFAULTS: &[(&str, &str, &str)] = &[
        (
            "python",
            "cpython-3.12.14",
            "sha256:3eaf7376260d22d2718eb9e08e0738195a6b859e169da152bc219d18313f9e40",
        ),
        (
            "node",
            "node-24.20.0",
            "sha256:3cb38df3f844d50b4e80ae966910f7a50e6356e95e8760f7ec7a9189f86c54f3",
        ),
        (
            "cargo",
            "rust-1.98.1",
            "sha256:625891abbb7049c43a74a4ef7066e8726e4a9e0df282a663f8eb1be826b1ecea",
        ),
        (
            "go",
            "go-1.27.0",
            "sha256:0052a56796a0ee06a5944d5d1bac2e607418eca7108ea066be24956660350fc7",
        ),
        (
            "ruby",
            "ruby-3.4.6",
            "sha256:d626f6fe2bf210af785f54bc2e697ae53b65e6512a0a206f98711659c7f5aae0",
        ),
        (
            "elixir",
            "beam-otp29.0.5-elixir1.20.4",
            "sha256:a465cce7520aa1206afd7ae6b171fc6090581d9f18d0abaf9221c657b40996b4",
        ),
        (
            "dotnet",
            "dotnet-sdk-9.0.317",
            "sha256:d56b9e135403ffc894a57c2ad1d855bb769be6f9465c7481f2b2ab35d4b0884f",
        ),
    ];

    /// Every release the hand-written tables shipped, with its bundle id:
    /// the catalogs are append-only, so each is still shipped, byte for
    /// byte, and every lock minted from one still names a catalog release.
    const SHIPPED_BEFORE_GROWTH: &[(&str, &str, &str)] = &[
        (
            "python",
            "cpython-3.14.7",
            "sha256:ddb9056bc192b606bf43c3fb352f59cc50e8008a746ed55ac1a593ec08d0a15e",
        ),
        (
            "python",
            "cpython-3.13.15",
            "sha256:cebc9ba6c9f0cb45067b12ef607d9a540241e67e14ed6fb88fce918529f5da2b",
        ),
        (
            "python",
            "cpython-3.12.14",
            "sha256:3eaf7376260d22d2718eb9e08e0738195a6b859e169da152bc219d18313f9e40",
        ),
        (
            "python",
            "cpython-3.11.16",
            "sha256:5a887a8f0b5f727bf2aabac10ed0ee7b465a36ec289c7e839240fa909fd36723",
        ),
        (
            "python",
            "cpython-3.10.21",
            "sha256:b8c28590bc35038a49c7b41b6ff6ce56f6be144b8f9fa943a1cd422bb1c2bf40",
        ),
        (
            "node",
            "node-24.20.0",
            "sha256:3cb38df3f844d50b4e80ae966910f7a50e6356e95e8760f7ec7a9189f86c54f3",
        ),
        (
            "node",
            "node-24.19.0",
            "sha256:402f7a0feb532a72dd2303c9c18c58d91d378c3ebc974b080d7070558c58a5fe",
        ),
        (
            "node",
            "node-24.18.1",
            "sha256:9bffc9f7c99d7433f2098e4f7e6588abf8aa09deb860121f98bf3e7ebd5fc2c7",
        ),
        (
            "node",
            "node-24.18.0",
            "sha256:a5180fe60d6f490f1b6c7ae53614c815eb6eaebe0e28a0bd9d988395bf03d806",
        ),
        (
            "node",
            "node-24.17.0",
            "sha256:38346968cbcb16e70f7303e9b2f5a53f182508d246c9844a911093455f742ee4",
        ),
        (
            "node",
            "node-24.16.0",
            "sha256:1cb138ee99612db4b7e5e879273b8e318502d94a4525f4bcda825bf7d4178bfe",
        ),
        (
            "node",
            "node-24.15.0",
            "sha256:1fef41d30024fe7615325ee5444f093ca8d7fef9d8d4683e7fc5972caf814ca5",
        ),
        (
            "node",
            "node-24.14.1",
            "sha256:0cb5af5ad46069f6116e927e62bf7bee6ddaeccbf51c47f3ff75e0072cb31576",
        ),
        (
            "node",
            "node-24.14.0",
            "sha256:3bcb72fd0eacf4be0f9afabc0341ceccda73da551b68b8cdfe749d3003662a90",
        ),
        (
            "node",
            "node-24.13.1",
            "sha256:976a3ec3833adf42946e6ac6b0cec2b6a23b8fe9fdda5d26e3e250b34a28852c",
        ),
        (
            "node",
            "node-24.13.0",
            "sha256:e39beb1f3c6b6f645e1694c0ebb33ebcafcb36c33a3dbeced01eab8515a53317",
        ),
        (
            "node",
            "node-24.12.0",
            "sha256:d2d7b1567fe88acce91b60eff4f58a0420109c6274bb720895c1563b1c1fd40e",
        ),
        (
            "node",
            "node-24.11.1",
            "sha256:ed13631e5f7529bb610f6a4e23b2f95b50d10c5c4bbed0a08dcb01ce53a0c001",
        ),
        (
            "node",
            "node-24.11.0",
            "sha256:558265d8d63b923d0d40e8084c9e507091510e0a65c27b67487b7ddf61d767bf",
        ),
        (
            "node",
            "node-22.23.2",
            "sha256:19ac32abd8cee03ba2d45272364ac5f54ab3ace69b4febd0c5ec2f0ac7b8d6b8",
        ),
        (
            "node",
            "node-22.23.1",
            "sha256:4250952c0376ea2859c4d4435843c50f8e53925f231731e1e4ac19014000a285",
        ),
        (
            "node",
            "node-22.23.0",
            "sha256:b31df06adc0bdadca602e76248cf7b6cfb75433f21fa7f69bd0e951c42baaafa",
        ),
        (
            "node",
            "node-22.22.3",
            "sha256:e30f7f7121a6a612e3a8a6123178ad09da0dc9c2dfab7e636fc2266f694027ca",
        ),
        (
            "node",
            "node-22.22.2",
            "sha256:3955400278e60a57ba382b83e69979d1f20440905e01e642904c5447d9e46297",
        ),
        (
            "node",
            "node-22.22.1",
            "sha256:d6c24aeb4a79ff2483381d5fb294b6b4b3a44338e9251a9f1fb457277682b748",
        ),
        (
            "node",
            "node-22.22.0",
            "sha256:085ca7b7aa7a55db0a5a514cad45d84f2f02d5fa539050cf46efa3a8a10e5da1",
        ),
        (
            "node",
            "node-22.21.1",
            "sha256:031e3e38307f7f00cc3662b3260b9cddf75638211e85d6d27d719cddce1fc515",
        ),
        (
            "node",
            "node-22.21.0",
            "sha256:a11189d95b3b855c36244bddd18692ef2c95a59bcea2aacf1a9763bc32ac065c",
        ),
        (
            "node",
            "node-22.20.0",
            "sha256:d91ecfe8b841cc99cc28191b50350e94d3d348228336ed38c33292f9883b653f",
        ),
        (
            "node",
            "node-22.19.0",
            "sha256:e6d38802d98120b0c22dc2730609a984d58547506d3289b7fbc38924b26b6a7a",
        ),
        (
            "node",
            "node-22.18.0",
            "sha256:d2203a70505b83062593dba197e37afa3efd625da3cadde7ee1760fc29eb9cf0",
        ),
        (
            "node",
            "node-22.17.1",
            "sha256:46b459608b3de5cce068293342e9743fb424eb9a0773c54f3d87bb37108d5f5e",
        ),
        (
            "node",
            "node-22.17.0",
            "sha256:633c54fe507f6e6175ad8c551a21172611d5263ef3ed84ae8e8368340b734211",
        ),
        (
            "node",
            "node-22.16.0",
            "sha256:57425b0880130f63c120cfd282364a457e5485633ced9e2cedf3372efeeb4461",
        ),
        (
            "node",
            "node-22.15.1",
            "sha256:ff8ede0cdc2a6d6dbde9af72fda72f5dbe6a13d7d7801dd7bdf21b79f242448a",
        ),
        (
            "node",
            "node-22.15.0",
            "sha256:b5d085facf7ef2d0214a225dc9f92066beb7994ce2381d1199f7f4dd39ecee1a",
        ),
        (
            "node",
            "node-22.14.0",
            "sha256:b16057acdbe7223f59056feee6ce0a78054dbe41a09b0ab0f8dda8c1f40d6be2",
        ),
        (
            "node",
            "node-22.13.1",
            "sha256:a52009c15da8e3c3c5b5bf138ba9762514bc1aa2bf813c940d1f2110d7018b43",
        ),
        (
            "node",
            "node-22.13.0",
            "sha256:b2f9aea47fca7f30f2b3b02c4ae5c0211ad5978cd80910bcab85184b2927fcb7",
        ),
        (
            "node",
            "node-22.12.0",
            "sha256:5944510f7a74697c82cca081b8516df794426e8c5ab64870e08b41915513ff99",
        ),
        (
            "node",
            "node-22.11.0",
            "sha256:c6cac9bb57646ae08a32a6853d523a14a1521de7ac6b9796b825ed2865ae920f",
        ),
        // The one Rust release the hand-written table shipped. Its bundle
        // gained the channel manifest row when the catalog became
        // generated (#134), so its id is the generated one; its base
        // object id is unchanged (see the cargo identity goldens).
        (
            "cargo",
            "rust-1.96.1",
            "sha256:b4b9a620da8759e882f1b1791d14203f0cbd96c5e51afb3407eb9ab7e75cd9fc",
        ),
        (
            "go",
            "go-1.27.0",
            "sha256:0052a56796a0ee06a5944d5d1bac2e607418eca7108ea066be24956660350fc7",
        ),
        (
            "ruby",
            "ruby-3.4.6",
            "sha256:d626f6fe2bf210af785f54bc2e697ae53b65e6512a0a206f98711659c7f5aae0",
        ),
        (
            "elixir",
            "beam-otp29.0.5-elixir1.20.4",
            "sha256:a465cce7520aa1206afd7ae6b171fc6090581d9f18d0abaf9221c657b40996b4",
        ),
        (
            "dotnet",
            "dotnet-sdk-9.0.317",
            "sha256:d56b9e135403ffc894a57c2ad1d855bb769be6f9465c7481f2b2ab35d4b0884f",
        ),
    ];

    #[test]
    fn the_shipped_defaults_and_every_earlier_release_are_unchanged() {
        for (ecosystem, release, id) in SHIPPED_DEFAULTS {
            let catalog = by_id(ecosystem).unwrap().toolchain_catalog().unwrap();
            let shipped = crate::kernel::toolchain::shipped(&catalog).unwrap();
            assert_eq!(&shipped.bundle.release, release, "{ecosystem}");
            assert_eq!(&shipped.bundle_id(), id, "{ecosystem}");
            // The empty request, which a project with no pin makes, is the
            // default too.
            assert_eq!(
                &catalog.select(&Request::newest()).unwrap().release,
                release,
                "{ecosystem}"
            );
        }
        for (ecosystem, release, id) in SHIPPED_BEFORE_GROWTH {
            let catalog = by_id(ecosystem).unwrap().toolchain_catalog().unwrap();
            let bundle = catalog
                .release(release)
                .unwrap_or_else(|| panic!("{ecosystem}: {release} is no longer shipped"));
            assert_eq!(&bundle.bundle_id(), id, "{ecosystem}: {release}");
        }
        // Every ecosystem grew.
        for tailor in registry() {
            let before = SHIPPED_BEFORE_GROWTH
                .iter()
                .filter(|(ecosystem, _, _)| *ecosystem == tailor.id())
                .count();
            let now = tailor.toolchain_catalog().unwrap().bundles().len();
            assert!(now > before, "{}: {now} releases", tailor.id());
        }
    }

    /// The generated documents, as the binary embeds them.
    const SHIPPED_DOCUMENTS: &[(&str, &str)] = &[
        (
            "python",
            include_str!("../kernel/provider/cpython.catalog.toml"),
        ),
        ("node", include_str!("node/catalog.toml")),
        ("go", include_str!("go/catalog.toml")),
        ("ruby", include_str!("ruby/catalog.toml")),
        ("elixir", include_str!("elixir/catalog.toml")),
        ("dotnet", include_str!("dotnet/catalog.toml")),
        (
            "cargo",
            include_str!("../kernel/provider/rust.catalog.toml"),
        ),
    ];

    /// Each document is in the canonical spelling `tools/catalog.py`
    /// writes, so a hand edit (or a generator that drifted from
    /// `Document::render`) fails here; and it is the catalog its tailor
    /// hands out.
    #[test]
    fn every_shipped_catalog_document_is_canonical_and_is_the_tailors_catalog() {
        use crate::kernel::toolchain::document::Document;
        for (ecosystem, text) in SHIPPED_DOCUMENTS {
            let document = Document::parse(text).unwrap_or_else(|e| panic!("{ecosystem}: {e}"));
            assert_eq!(&document.ecosystem, ecosystem);
            assert!(
                document.render().unwrap() == *text,
                "{ecosystem}: the document is not in canonical form; regenerate it with \
                 `python3 tools/catalog.py {ecosystem}`"
            );
            let catalog = by_id(ecosystem).unwrap().toolchain_catalog().unwrap();
            assert_eq!(
                catalog.bundles(),
                document.bundles.as_slice(),
                "{ecosystem}"
            );
            assert_eq!(
                catalog.default_release().unwrap().release,
                document.default,
                "{ecosystem}"
            );
            // One release per upstream version, unless the generator added
            // a re-published one as a higher explicit revision beside it.
            let mut versions = std::collections::BTreeSet::new();
            for bundle in &document.bundles {
                assert!(
                    versions.insert((bundle.primary_versions().unwrap(), bundle.revision)),
                    "{ecosystem}: {} repeats a version and revision",
                    bundle.release
                );
            }
        }
    }

    /// A pre-lock closure body per ecosystem, shaped as the writers shape
    /// it (the platform lives in the envelope, never in the body), recording
    /// the versions of `bundle`.
    fn legacy_body(id: &str, bundle: &crate::kernel::toolchain::Bundle) -> Value {
        let version = |component: &str| bundle.component(component).unwrap().version.clone();
        match id {
            "python" => json!({"python": {"version": version("cpython")}, "plan": {}}),
            "node" => json!({"node_version": version("node")}),
            "cargo" => json!({"plan": {"rust_version": version("rustc")}}),
            "go" => json!({"plan": {"go_version": version("go")}}),
            "ruby" => json!({"plan": {"ruby_version": version("ruby")}}),
            "elixir" => {
                json!({"plan": {"otp_version": version("otp"), "elixir_version": version("elixir")}})
            }
            "dotnet" => json!({"plan": {"sdk_version": version("dotnet-sdk")}}),
            other => panic!("no legacy body for {other}"),
        }
    }

    #[test]
    fn legacy_closures_seed_the_release_they_record_or_refuse() {
        for tailor in registry() {
            let catalog = tailor.toolchain_catalog().unwrap();
            let newest = catalog.select(&Request::newest()).unwrap();
            // Every release the catalog ships, the older ones included: a
            // seed that ignored the record and returned the newest release
            // passes for the newest alone.
            let mut seeded_an_older_release = false;
            for bundle in catalog.bundles() {
                let body = legacy_body(tailor.id(), bundle);
                assert!(body.get("platform").is_none());
                let versions = bundle.primary_versions().unwrap();
                // A re-published revision shares its versions with another
                // release; the record cannot tell those apart.
                let unique = catalog
                    .bundles()
                    .iter()
                    .filter(|other| other.primary_versions().unwrap() == versions)
                    .count()
                    == 1;
                for platform in Platform::ALL {
                    let evidence =
                        tailor.legacy_toolchain_evidence(tailor.id(), Some(*platform), &body, None);
                    assert_eq!(evidence.platform, Some(*platform));
                    let seeded = seed(&catalog, &evidence)
                        .unwrap_or_else(|error| panic!("{}: {error}", tailor.id()));
                    assert_eq!(
                        seeded.primary_versions().unwrap(),
                        versions,
                        "{} {}",
                        tailor.id(),
                        bundle.release
                    );
                    if unique {
                        assert_eq!(seeded.release, bundle.release, "{}", tailor.id());
                    }
                }
                if unique && bundle.release != newest.release {
                    seeded_an_older_release = true;
                }
            }
            assert!(
                seeded_an_older_release,
                "{}: no older release was seeded",
                tailor.id()
            );
            let body = legacy_body(tailor.id(), newest);
            // No envelope platform: refuse, naming the update verb.
            let evidence = tailor.legacy_toolchain_evidence(tailor.id(), None, &body, None);
            let error = seed(&catalog, &evidence).unwrap_err();
            assert!(
                error.to_string().contains("records no platform"),
                "{}: {error}",
                tailor.id()
            );
            assert!(
                error.to_string().contains("tog update --toolchain"),
                "{}: {error}",
                tailor.id()
            );
            // No recorded version: refuse rather than use the shipped default.
            let bare = json!({"plan": {}});
            let evidence = tailor.legacy_toolchain_evidence(tailor.id(), Some(LINUX), &bare, None);
            let error = seed(&catalog, &evidence).unwrap_err();
            assert!(
                error.to_string().contains("records no"),
                "{}: {error}",
                tailor.id()
            );
        }
        // Python's older closures record the version on the plan instead.
        let python = by_id("python").unwrap();
        let catalog = python.toolchain_catalog().unwrap();
        let old = json!({"plan": {"python_version": "3.11.16"}});
        let seeded = seed(
            &catalog,
            &python.legacy_toolchain_evidence("python", Some(DARWIN), &old, None),
        )
        .unwrap();
        assert_eq!(seeded.component("cpython").unwrap().version, "3.11.16");
        // A rustfmt closure records the version at the top level.
        let cargo = by_id("cargo").unwrap();
        let catalog = cargo.toolchain_catalog().unwrap();
        let fmt = json!({"rust_version": "1.96.1"});
        assert!(seed(
            &catalog,
            &cargo.legacy_toolchain_evidence("rustfmt", Some(LINUX), &fmt, None)
        )
        .is_ok());
        // A version the catalog never shipped is unrecoverable.
        let stranger = json!({"plan": {"rust_version": "1.0.0"}});
        let error = seed(
            &catalog,
            &cargo.legacy_toolchain_evidence("cargo", Some(LINUX), &stranger, None),
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("no catalog release has rustc 1.0.0"),
            "{error}"
        );
    }

    /// The runtime object(s) a pre-lock sync of `id` from `selected` left in
    /// `store`, and the closure body fields naming them.
    fn legacy_runtime(
        id: &str,
        platform: Platform,
        selected: &Selected,
        store: &crate::kernel::store::Store,
    ) -> (Value, Vec<crate::kernel::types::Identity>) {
        match id {
            "python" => python::legacy_runtime_for_test(platform, selected, store),
            "node" => node::legacy_runtime_for_test(platform, selected, store),
            "cargo" => cargo::legacy_runtime_for_test(platform, selected, store),
            "go" => go::legacy_runtime_for_test(platform, selected, store),
            "ruby" => ruby::legacy_runtime_for_test(platform, selected, store),
            "elixir" => elixir::legacy_runtime_for_test(platform, selected, store),
            "dotnet" => dotnet::legacy_runtime_for_test(platform, selected, store),
            other => panic!("no legacy runtime for {other}"),
        }
    }

    /// `bundle` rebuilt: the same versions under a second revision whose
    /// every artifact digest differs, so only an artifact tells them apart.
    fn rebuilt(bundle: &crate::kernel::toolchain::Bundle) -> crate::kernel::toolchain::Bundle {
        use crate::kernel::digest::Digest;
        let mut twin = bundle.clone();
        twin.release = format!("{}-rebuilt", bundle.release);
        twin.revision = Some(2);
        for row in &mut twin.artifacts {
            let hex: String = row
                .digest
                .hex()
                .chars()
                .map(|c| if c == '0' { '1' } else { '0' })
                .collect();
            row.digest = match row.digest.algo() {
                "sha256" => Digest::sha256(&hex),
                _ => Digest::sha512(&hex),
            }
            .unwrap();
        }
        twin
    }

    fn with_refs(mut body: Value, refs: &Value) -> Value {
        for (key, value) in refs.as_object().unwrap() {
            body[key] = value.clone();
        }
        body
    }

    fn scratch_store(
        temp: &crate::kernel::testutil::TempDir,
        name: &str,
    ) -> crate::kernel::store::Store {
        let root = temp.0.join(name);
        for sub in ["objects", "meta"] {
            std::fs::create_dir_all(root.join(sub)).unwrap();
        }
        crate::kernel::store::Store {
            root: root.canonicalize().unwrap(),
        }
    }

    /// #133: when two releases share the recorded version, the closure's
    /// runtime object decides, read through the active store; an object the
    /// store does not hold proves nothing, and one that contradicts the
    /// closure refuses. Every tailor, both platforms.
    #[test]
    fn legacy_seeding_needs_the_store_object_when_versions_tie() {
        use crate::comforter::toolchain::publish_for_test;
        use crate::kernel::toolchain::Source;
        let temp = crate::kernel::testutil::TempDir::new();
        for tailor in registry() {
            let id = tailor.id();
            let shipped = tailor.toolchain_catalog().unwrap();
            let mut first = shipped.select(&Request::newest()).unwrap().clone();
            first.revision = Some(1);
            let second = rebuilt(&first);
            let catalog =
                Catalog::new(shipped.ecosystem(), vec![first.clone(), second.clone()]).unwrap();
            let selected = |bundle: &crate::kernel::toolchain::Bundle| Selected {
                helpers: Default::default(),
                ecosystem: tailor.lock_ecosystem().to_string(),
                bundle: bundle.clone(),
                lock_sha256: None,
                source: Source::Shipped,
            };
            let versions = legacy_body(id, &first);
            for platform in Platform::ALL.iter().copied() {
                let other = *Platform::ALL.iter().find(|p| **p != platform).unwrap();
                let store = scratch_store(&temp, &format!("{id}-{}", platform.triple()));
                let evidence = |body: &Value, store: Option<&crate::kernel::store::Store>| {
                    tailor.legacy_toolchain_evidence(id, Some(platform), body, store)
                };
                let seeds = |body: &Value, store| seed(&catalog, &evidence(body, store));

                // Each release's own object proves that release.
                for bundle in [&first, &second] {
                    let (refs, objects) = legacy_runtime(id, platform, &selected(bundle), &store);
                    for object in &objects {
                        publish_for_test(&store, object);
                    }
                    let body = with_refs(versions.clone(), &refs);
                    let proved = evidence(&body, Some(&store));
                    assert!(proved.unproved.is_empty(), "{id}: {:?}", proved.unproved);
                    assert!(!proved.artifacts.is_empty(), "{id}");
                    let seeded = seed(&catalog, &proved)
                        .unwrap_or_else(|error| panic!("{id} {platform:?}: {error}"));
                    assert_eq!(seeded.release, bundle.release, "{id} {platform:?}");
                }
                let (refs, objects) = legacy_runtime(id, platform, &selected(&first), &store);
                let body = with_refs(versions.clone(), &refs);

                // Versions alone cannot choose, and the refusal says why no
                // object proved anything.
                let error = seeds(&body, None).unwrap_err().to_string();
                assert!(error.contains("all have"), "{id}: {error}");
                assert!(error.contains("there is no store"), "{id}: {error}");
                let empty = scratch_store(&temp, &format!("{id}-{}-empty", platform.triple()));
                let (absent, _) = legacy_runtime(id, platform, &selected(&first), &empty);
                let error = seeds(&with_refs(versions.clone(), &absent), Some(&empty))
                    .unwrap_err()
                    .to_string();
                assert!(error.contains("all have"), "{id}: {error}");
                assert!(error.contains("is not in the store at"), "{id}: {error}");
                assert!(error.contains("tog update --toolchain"), "{id}: {error}");
                // A reference recorded in another store is not read there.
                let error = seeds(&body, Some(&empty)).unwrap_err().to_string();
                assert!(error.contains("all have"), "{id}: {error}");
                assert!(error.contains("recorded in another store"), "{id}: {error}");

                // An object of another kind under the reference refuses.
                let stranger = crate::kernel::types::Identity {
                    kind: "test".into(),
                    name: "stranger".into(),
                    version: "1".into(),
                    inputs: Default::default(),
                };
                let stranger_id = publish_for_test(&store, &stranger);
                let named = objects
                    .iter()
                    .map(|object| object.object_id())
                    .find(|object| refs.to_string().contains(object.as_str()))
                    .unwrap();
                let swapped: Value =
                    serde_json::from_str(&refs.to_string().replace(&named, &stranger_id)).unwrap();
                let error = seeds(&with_refs(versions.clone(), &swapped), Some(&store))
                    .unwrap_err()
                    .to_string();
                assert!(error.contains("is a test object"), "{id}: {error}");

                // An object built for the other platform refuses.
                let (foreign_refs, foreign) = legacy_runtime(id, other, &selected(&first), &store);
                for object in &foreign {
                    publish_for_test(&store, object);
                }
                let error = seeds(&with_refs(versions.clone(), &foreign_refs), Some(&store))
                    .unwrap_err()
                    .to_string();
                assert!(error.contains("was built for"), "{id}: {error}");

                // A version edited beside an untouched object refuses,
                // whatever the catalog holds.
                let mut edited = first.clone();
                for component in &mut edited.components {
                    if edited.primary.contains(&component.name) {
                        component.version = "0.0.1".into();
                    }
                }
                let error = seeds(&with_refs(legacy_body(id, &edited), &refs), Some(&store))
                    .unwrap_err()
                    .to_string();
                assert!(error.contains("0.0.1 but its"), "{id}: {error}");
            }
        }
    }

    /// Once the store holds the object a closure names, an identity the
    /// tailor cannot read as its own is a contradiction: it refuses even a
    /// version only one release carries, where no proof would be needed.
    #[test]
    fn a_found_object_with_a_malformed_identity_refuses_a_unique_version() {
        use crate::comforter::toolchain::{object_ref_for_test, publish_for_test};
        use crate::kernel::toolchain::Source;
        let temp = crate::kernel::testutil::TempDir::new();
        let platform = LINUX;
        type Mutate = fn(&mut crate::kernel::types::Identity);
        let cases: [(&str, &str, usize, Mutate, &str); 7] = [
            (
                "python",
                "/env_object",
                1,
                |env| {
                    env.inputs
                        .insert("cpython".into(), "not-an-object-id".into());
                },
                "names no well-formed cpython object id",
            ),
            (
                "node",
                "/env_object",
                1,
                |env| {
                    env.inputs.remove("nodejs");
                },
                "names no well-formed nodejs object id",
            ),
            (
                "go",
                "/go_object",
                0,
                |go| {
                    go.inputs.remove("artifact_sha256");
                },
                "records no artifact_sha256",
            ),
            (
                "cargo",
                "/rust_object",
                0,
                |rust| {
                    rust.inputs.remove("cargo_sha256");
                },
                "records no cargo_sha256",
            ),
            (
                "ruby",
                "/ruby_object",
                0,
                |ruby| {
                    ruby.inputs.remove("schema");
                },
                "records no recipe",
            ),
            (
                "dotnet",
                "/sdk_object",
                0,
                |sdk| {
                    sdk.inputs.insert("artifact_sha512".into(), "zz".into());
                },
                "has a malformed artifact_sha512",
            ),
            (
                "elixir",
                "/beam_object",
                0,
                |beam| {
                    beam.version = "29.0.5".into();
                },
                "records no OTP/Elixir pair",
            ),
        ];
        for (id, pointer, index, mutate, why) in cases {
            let tailor = by_id(id).unwrap();
            let catalog = tailor.toolchain_catalog().unwrap();
            let bundle = catalog.select(&Request::newest()).unwrap().clone();
            let selected = Selected {
                helpers: Default::default(),
                ecosystem: tailor.lock_ecosystem().to_string(),
                bundle: bundle.clone(),
                lock_sha256: None,
                source: Source::Shipped,
            };
            let store = scratch_store(&temp, id);
            let (_, mut objects) = legacy_runtime(id, platform, &selected, &store);
            mutate(&mut objects[index]);
            for object in &objects {
                publish_for_test(&store, object);
            }
            let named = objects[index].object_id();
            let reference = if pointer == "/env_object" {
                json!(store.object_path(&named))
            } else {
                object_ref_for_test(&store, &named)
            };
            let mut body = legacy_body(id, &bundle);
            body[&pointer[1..]] = reference;
            // Unmodified, the version alone seeds this catalog.
            let bare = tailor.legacy_toolchain_evidence(id, Some(platform), &body, None);
            assert!(seed(&catalog, &bare).is_ok(), "{id}");
            let evidence =
                tailor.legacy_toolchain_evidence(id, Some(platform), &body, Some(&store));
            assert!(
                evidence.unproved.is_empty(),
                "{id}: {:?}",
                evidence.unproved
            );
            let error = seed(&catalog, &evidence).unwrap_err().to_string();
            assert!(error.contains(why), "{id}: {error}");
            assert!(error.contains("tog update --toolchain"), "{id}: {error}");
        }
    }

    /// A malformed reference contradicts the closure before any store is
    /// consulted, so it refuses a uniquely versioned release with or
    /// without a store; so does an `{id, path}` pair whose path names
    /// another object than its id.
    #[test]
    fn a_malformed_reference_refuses_a_unique_version_with_or_without_a_store() {
        use crate::comforter::toolchain::publish_for_test;
        use crate::kernel::toolchain::Source;
        let temp = crate::kernel::testutil::TempDir::new();
        let store = scratch_store(&temp, "refs");
        let go = by_id("go").unwrap();
        let catalog = go.toolchain_catalog().unwrap();
        let bundle = catalog.select(&Request::newest()).unwrap().clone();
        let selected = Selected {
            helpers: Default::default(),
            ecosystem: "go".into(),
            bundle: bundle.clone(),
            lock_sha256: None,
            source: Source::Shipped,
        };
        let (_, objects) = legacy_runtime("go", LINUX, &selected, &store);
        let real = publish_for_test(&store, &objects[0]);
        let mut other = objects[0].clone();
        other.name = "go-other".into();
        let other = publish_for_test(&store, &other);
        let refusal = |body: &Value, store: Option<&crate::kernel::store::Store>| {
            let evidence = go.legacy_toolchain_evidence("go", Some(LINUX), body, store);
            seed(&catalog, &evidence).unwrap_err().to_string()
        };
        let with = |reference: Value| {
            let mut body = legacy_body("go", &bundle);
            body["go_object"] = reference;
            body
        };
        // The version alone seeds this catalog.
        let bare =
            go.legacy_toolchain_evidence("go", Some(LINUX), &legacy_body("go", &bundle), None);
        assert!(seed(&catalog, &bare).is_ok());
        for reference in [
            json!(42),
            json!("relative/not-an-object"),
            json!({"id": "not-an-id", "path": store.object_path("not-an-id")}),
            json!({"id": real}),
            json!({"id": real, "path": store.object_path(&other)}),
        ] {
            for store in [None, Some(&store)] {
                let error = refusal(&with(reference.clone()), store);
                assert!(
                    error.contains("object reference is malformed"),
                    "{reference}: {error}"
                );
            }
        }
        let error = refusal(
            &with(json!({"id": real, "path": store.object_path(&other)})),
            Some(&store),
        );
        assert!(
            error.contains("is not the object its path names"),
            "{error}"
        );
        // A null reference names nothing: the version alone still seeds.
        let evidence =
            go.legacy_toolchain_evidence("go", Some(LINUX), &with(Value::Null), Some(&store));
        assert!(seed(&catalog, &evidence).is_ok());
    }

    #[test]
    fn an_unconstrained_python_project_keeps_the_shipped_default() {
        use crate::kernel::toolchain::input::InputRow;
        use crate::kernel::toolchain::select_for;
        let catalog = by_id("python").unwrap().toolchain_catalog().unwrap();
        let row = |path: &str, field: &str, value: Option<&str>| InputRow {
            path: std::path::PathBuf::from(path),
            field: field.into(),
            value: value.map(str::to_string),
            absent: value.is_none(),
            sha256: value.map(|_| "a".repeat(64)),
        };
        let rows = |version: Option<&str>, requires: Option<&str>| {
            vec![
                row(".python-version", "version", version),
                row("pyproject.toml", "project.requires-python", requires),
                row("pyproject.toml", "tool.poetry.dependencies.python", None),
            ]
        };
        let version = |rows: &[InputRow]| {
            select_for(&catalog, "python", rows)
                .unwrap()
                .component("cpython")
                .unwrap()
                .version
                .clone()
        };
        assert_eq!(
            version(&rows(None, None)),
            crate::tailors::python::pyselect::DEFAULT_VERSION
        );
        assert_eq!(
            version(&rows(None, Some(">=3.9"))),
            crate::tailors::python::pyselect::DEFAULT_VERSION
        );
        assert_eq!(version(&rows(None, Some(">=3.13"))), "3.14.7");
        assert_eq!(version(&rows(Some("3.13"), None)), "3.13.15");
        assert_eq!(version(&rows(Some("3.11.16"), Some(">=3.9"))), "3.11.16");
    }
}

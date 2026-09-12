//! The tailors: one folder per ecosystem adapter. Each tailor is a leaf of
//! the module graph: it depends on the kernel and the comforter, never on
//! another tailor or on a command (REFACTOR.md §2).
//!
//! `Tailor` is the one blueprint every ecosystem implements and
//! `registry()` is the only list of ecosystems in the crate. A command
//! iterates the registry; it never names an ecosystem. Adding an ecosystem
//! is a folder plus one line in `REGISTRY` (docs/human/ADDING-A-TAILOR.md).

pub mod cargo;
pub mod dotnet;
pub mod elixir;
pub mod go;
pub mod node;
pub mod python;
pub mod ruby;

use crate::comforter::status::State;
use crate::kernel::context::Context;
use crate::kernel::objmeta::KindAdapter;
use crate::kernel::platform::Platform;
use serde_json::Value;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

/// One row of `blanket ls`.
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

/// One `blanket doctor` line contributed by a tailor.
#[derive(Debug, Clone)]
pub struct DoctorCheck {
    pub name: &'static str,
    pub ok: bool,
    pub detail: String,
}

fn unsupported(id: &str, verb: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        format!("blanket {verb} does not support {id}"),
    )
}

/// The verbs every ecosystem answers. Methods with a default body are the
/// optional ones: not every ecosystem builds, contributes run-time
/// environment, or has doctor checks.
///
/// Every method takes the project directory explicitly: a tailor never reads
/// the current directory itself, so the same tailor can serve `sync` in
/// `dir` and `build` in a workspace root above it.
pub trait Tailor: Sync {
    /// The ecosystem name: closure file stem, `ls` vocabulary, plan JSON.
    fn id(&self) -> &'static str;

    /// Does this tailor own the closure file `.blanket/closures/<name>.json`?
    /// A tailor that writes a second closure kind (cargo's `rustfmt`)
    /// overrides this.
    fn owns_closure(&self, name: &str) -> bool {
        name == self.id()
    }

    /// Are this ecosystem's inputs present in `dir` itself? The one test
    /// `sync`, `plan`, `status`, `deps`, and `fmt` all use.
    fn detect(&self, dir: &Path) -> io::Result<bool>;

    /// Before any store-touching work: host support and toolchain pin.
    fn preflight(&self, platform: Platform, dir: &Path) -> io::Result<()>;

    /// Host-side preparation that must precede planning for every
    /// ecosystem (missing-lock generation). Runs for detected ecosystems
    /// only, before any of them plans.
    fn prepare(&self, _ctx: &Context, _dir: &Path) -> io::Result<()> {
        Ok(())
    }

    /// `blanket plan`: the plan as pretty-printed JSON text, without
    /// realizing anything. `None` when, after `prepare`, there is nothing of
    /// this ecosystem to plan (the text is produced here, not a `Value`, so
    /// each plan's key order stays exactly what its producer serializes).
    fn plan(&self, ctx: &Context, dir: &Path) -> io::Result<Option<String>>;

    /// `blanket sync`: plan, realize, project, and narrate with
    /// `ui::synced`. Returns whether anything was synced.
    fn sync(&self, ctx: &Context, dir: &Path, fresh: bool) -> io::Result<bool>;

    /// Can `blanket build <id>` name this ecosystem at all?
    fn builds(&self) -> bool {
        false
    }

    /// `blanket build` inference: is there something of this ecosystem to
    /// build from `cwd`? (Ancestor search where the ecosystem supports it.)
    fn build_present(&self, _cwd: &Path) -> io::Result<bool> {
        Ok(false)
    }

    /// The directory `blanket build` roots at for this ecosystem from `cwd`.
    fn build_root(&self, _cwd: &Path) -> io::Result<PathBuf> {
        Err(unsupported(self.id(), "build"))
    }

    /// Plan, realize, project, then run the sandboxed build in `root`.
    fn build(&self, _ctx: &Context, _root: &Path, _cwd: &Path, _args: &[String]) -> io::Result<()> {
        Err(unsupported(self.id(), "build"))
    }

    /// `blanket run`: the PATH prefixes and environment this ecosystem's
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

    /// `blanket ls`: what a closure of this ecosystem lists.
    fn listing(&self, ecosystem: &str, body: &Value) -> ClosureListing;

    /// `blanket status`: is the closure's projection still current?
    fn closure_state(
        &self,
        platform: Platform,
        dir: &Path,
        ecosystem: &str,
        body: &Value,
    ) -> io::Result<State>;

    /// `blanket doctor`: project-level checks specific to this ecosystem.
    fn doctor(&self, _platform: Platform, _dir: &Path) -> Vec<DoctorCheck> {
        Vec::new()
    }

    /// `blanket sbom`: CycloneDX components for a closure of this ecosystem.
    fn sbom_components(
        &self,
        ecosystem: &str,
        body: &Value,
        out: &mut Vec<Value>,
    ) -> io::Result<()>;

    /// The store object kinds this tailor produces: their identity grammar
    /// and legacy-metadata adapters (`objmeta`). Every kind a tailor commits
    /// must have a row here or GC refuses to certify its records.
    fn object_kinds(&self) -> &'static [KindAdapter] {
        &[]
    }

    /// The `--eco` word `blanket fmt` accepts for this ecosystem, when it
    /// has a pinned formatter.
    fn fmt_ecosystem(&self) -> Option<&'static str> {
        None
    }

    /// `blanket fmt`, before the store is opened: refuse a host with no
    /// pinned formatter component.
    fn fmt_preflight(&self, _platform: Platform) -> io::Result<()> {
        Err(unsupported(self.id(), "fmt"))
    }

    /// `blanket fmt`, before the store is opened: is there a project of this
    /// ecosystem to format from `cwd`?
    fn fmt_check_project(&self, _cwd: &Path) -> io::Result<()> {
        Err(unsupported(self.id(), "fmt"))
    }

    /// `blanket fmt`: realize the formatter, record its closure, and run it
    /// sandboxed over the workspace `cwd` belongs to.
    fn fmt(&self, _ctx: &Context, _cwd: &Path, _check: bool, _args: &[String]) -> io::Result<i32> {
        Err(unsupported(self.id(), "fmt"))
    }
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

/// The tailor that wrote `.blanket/closures/<name>.json`, if any.
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

/// Hand the kernel every tailor's object-kind rows. `commands::dispatch`
/// calls this once before any command runs; tests that adapt tailor kinds
/// through `objmeta` or `gc` call it in their setup. Idempotent.
pub fn install_kinds() {
    crate::kernel::objmeta::install_kinds(kind_adapters());
}

/// The tailors whose inputs are present in `dir`, in registry order.
pub fn detected(dir: &Path) -> io::Result<Vec<&'static dyn Tailor>> {
    let mut found = Vec::new();
    for tailor in registry() {
        if tailor.detect(dir)? {
            found.push(*tailor);
        }
    }
    Ok(found)
}

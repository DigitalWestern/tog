//! The tailors: one folder per ecosystem adapter. Each tailor is a leaf of
//! the module graph: it depends on the kernel and the comforter, never on
//! another tailor or on a command.
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
use crate::kernel::toolchain::{Catalog, LegacyEvidence, Selected};
use serde_json::Value;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

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
/// and the toolchain it must use. `frozen` never reaches a tailor that is
/// allowed to write project inputs; the caller skips `prepare` entirely.
pub struct SyncRequest<'a> {
    pub fresh: bool,
    pub frozen: bool,
    pub toolchain: &'a Selected,
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

    /// Are this ecosystem's inputs present in `dir` itself? The one test
    /// `sync`, `plan`, `status`, `deps`, and `fmt` all use.
    fn detect(&self, dir: &Path) -> io::Result<bool>;

    /// Before any store-touching work: host support and toolchain pin.
    fn preflight(&self, platform: Platform, dir: &Path) -> io::Result<()>;

    /// Host-side preparation that must precede planning for every
    /// ecosystem (missing-lock generation). Runs for detected ecosystems
    /// only, before any of them plans.
    fn prepare(
        &self,
        _ctx: &Context,
        _dir: &Path,
        _toolchain: &Selected,
        _attribution: &mut crate::kernel::policy::Attribution,
    ) -> io::Result<()> {
        Ok(())
    }

    /// `tog plan`: the plan as pretty-printed JSON text, without
    /// realizing anything. `None` when, after `prepare`, there is nothing of
    /// this ecosystem to plan (the text is produced here, not a `Value`, so
    /// each plan's key order stays exactly what its producer serializes).
    fn plan(&self, ctx: &Context, dir: &Path, toolchain: &Selected) -> io::Result<Option<String>>;

    /// A sync: plan, realize, project, and narrate with
    /// `ui::synced`. Returns whether anything was synced.
    fn sync(
        &self,
        ctx: &Context,
        dir: &Path,
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

    /// The shipped toolchain catalog: this ecosystem's pin tables as release
    /// bundles (`kernel::toolchain`), the rows a toolchain lock is minted
    /// from. Selection and legacy seeding read it; realization keeps reading
    /// the pin tables, so no object identity changes.
    fn toolchain_catalog(&self) -> io::Result<Catalog>;

    /// What a closure of this ecosystem written before the toolchain lock
    /// proves about its toolchain (`kernel::toolchain::seed`): `platform`
    /// is the closure envelope's platform, `body` the closure body
    /// `read_closure` returns, from which the exact recorded versions come.
    fn legacy_toolchain_evidence(
        &self,
        ecosystem: &str,
        platform: Option<Platform>,
        body: &Value,
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

    /// `tog x`: how this ecosystem runs a tool straight from its public
    /// registry, when it can.
    fn registry_tool(&self) -> io::Result<&'static dyn RegistryTool> {
        Err(unsupported(self.id(), "x"))
    }
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

    /// Resolve `package` (exactly `version`, or the registry's latest),
    /// realize it on `toolchain`, and project it into `root`.
    #[allow(clippy::too_many_arguments)]
    fn realize(
        &self,
        store: &crate::kernel::store::Store,
        activity: &crate::kernel::activity::StoreActivity,
        platform: Platform,
        root: &Path,
        package: &str,
        version: Option<&str>,
        toolchain: &Selected,
        attribution: &mut crate::kernel::policy::Attribution,
    ) -> io::Result<()>;

    /// What an executable launched from a realized `root` runs with.
    fn launch_env(
        &self,
        store: &crate::kernel::store::Store,
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
    let mut found = Vec::new();
    for tailor in registry() {
        if tailor.detect(dir)? {
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

    #[test]
    fn every_tailor_ships_a_complete_catalog_under_the_shipped_source_policy() {
        let policy = SourcePolicy::shipped();
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
        // Two platforms each for the SDK, Hex and rebar3.
        assert_eq!(seen, 6);
        // Python: five CPython releases, each with the one pinned uv.
        let python = by_id("python").unwrap().toolchain_catalog().unwrap();
        assert_eq!(python.bundles().len(), 5);
        for bundle in python.bundles() {
            assert_eq!(bundle.components.len(), 2);
            assert_eq!(bundle.artifacts.len(), 4);
            assert!(bundle.artifact(LINUX, "uv").is_some());
        }
        // BEAM: the pair is primary, OTP first, and the Linux OTP row names
        // the relocation recipe the Linux identity already commits to.
        let elixir = by_id("elixir").unwrap().toolchain_catalog().unwrap();
        let beam = &elixir.bundles()[0];
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
        // Rust: rustfmt rides in the same bundle under its own recipe.
        let cargo = by_id("cargo").unwrap().toolchain_catalog().unwrap();
        let rust = &cargo.bundles()[0];
        assert_eq!(rust.components.len(), 4);
        assert_eq!(rust.artifact(LINUX, "rustfmt").unwrap().recipe, "rustfmt/1");
        assert_eq!(
            rust.artifact(LINUX, "rustc").unwrap().recipe,
            "rust-toolchain/1"
        );
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
            let body = legacy_body(tailor.id(), newest);
            assert!(body.get("platform").is_none());
            for platform in Platform::ALL {
                let evidence =
                    tailor.legacy_toolchain_evidence(tailor.id(), Some(*platform), &body);
                assert_eq!(evidence.platform, Some(*platform));
                let seeded = seed(&catalog, &evidence)
                    .unwrap_or_else(|error| panic!("{}: {error}", tailor.id()));
                assert_eq!(seeded.release, newest.release, "{}", tailor.id());
            }
            // No envelope platform: refuse, naming the update verb.
            let evidence = tailor.legacy_toolchain_evidence(tailor.id(), None, &body);
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
            let evidence = tailor.legacy_toolchain_evidence(tailor.id(), Some(LINUX), &bare);
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
            &python.legacy_toolchain_evidence("python", Some(DARWIN), &old),
        )
        .unwrap();
        assert_eq!(seeded.component("cpython").unwrap().version, "3.11.16");
        // A rustfmt closure records the version at the top level.
        let cargo = by_id("cargo").unwrap();
        let catalog = cargo.toolchain_catalog().unwrap();
        let fmt = json!({"rust_version": "1.96.1"});
        assert!(seed(
            &catalog,
            &cargo.legacy_toolchain_evidence("rustfmt", Some(LINUX), &fmt)
        )
        .is_ok());
        // A version the catalog never shipped is unrecoverable.
        let stranger = json!({"plan": {"rust_version": "1.0.0"}});
        let error = seed(
            &catalog,
            &cargo.legacy_toolchain_evidence("cargo", Some(LINUX), &stranger),
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("no catalog release has rustc 1.0.0"),
            "{error}"
        );
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

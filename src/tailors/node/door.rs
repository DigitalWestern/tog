//! Running the store npm and the pinned pnpm as resolvers (node tailor):
//! confined through the door, their https traffic intercepted by the proxy
//! session (the registry through the [`registry`](super::registry) route,
//! git dependencies through the git row, a scoped registry or a direct-URL
//! tarball as `unattested-index`).
//!
//! Every Node resolution goes through here: `tog add`/`remove`/`update`, a
//! missing `package-lock.json`, `tog x`'s npm resolution, and `tog
//! attest`'s lock checks. None runs npm or pnpm directly.
//!
//! How the tools are pointed at the session, on the command line, where
//! both give flags priority over `.npmrc`:
//!
//! - npm: `--proxy` and `--https-proxy` with the session token as
//!   credentials, `--noproxy=` so no host bypasses it, `--registry` the
//!   public registry, `--strict-ssl=true` with `--cafile` the session CA
//!   (which replaces npm's roots, PR 0), `--update-notifier=false`,
//!   `--audit=false` and `--fund=false` (each otherwise a request that is
//!   not resolution), and `--cache` in the run's scratch.
//! - pnpm: the same settings as `--config.<key>=<value>`, the one spelling
//!   every pnpm verb's parser accepts (PR 0: `pnpm remove` rejects
//!   `--proxy`), plus its modules state and store pointed into the scratch
//!   (`enable-modules-dir=false`, `node-linker=isolated`, `modules-dir`,
//!   `virtual-store-dir`, `store-dir`), so the lock-only run never touches
//!   a `node_modules`.
//! - Both: `NODE_EXTRA_CA_CERTS` and the proxy environment for any other
//!   Node code, and `NPM_CONFIG_AUDIT`, `FUND`, and `UPDATE_NOTIFIER`
//!   off for the child npm pacote starts for a git dependency.
//!
//! The forced program settings (`--git`, `--script-shell`, `--shell`,
//! `--ignore-scripts`, `--node-options=`, pnpm's `pnpmfile` pair) come from
//! the forced-settings table, and the door checks they are present. The
//! programs they name are the host git and shell the sandbox's read-only
//! system roots carry: tog provisions no git or shell of its own.

use super::registry;
use crate::kernel::resolve::confine;
use crate::kernel::resolve::door::{self, ConfinedSpec, Publish, Wire, Wiring};
use crate::kernel::resolve::record;
use crate::kernel::resolve::session::Intercept;
use crate::kernel::resolve::snapshot::PathGlob;
use crate::kernel::resolve::{DelegateReport, DelegateSpec, ResolutionDoor};
use std::ffi::OsString;
use std::io;
use std::path::{Component, Path, PathBuf};

/// Why npm runs isolated, for the missing-capability message.
pub(crate) const WHY_NPM: &str = "runs the git and script-shell programs a project's .npmrc \
                                  names, and fetches packages from the network";
/// Why pnpm runs isolated.
pub(crate) const WHY_PNPM: &str = "runs the script-shell program a project's .npmrc names \
                                   and the project's .pnpmfile.cjs, and fetches packages from \
                                   the network";

/// The git every npm and pnpm run starts for a git dependency, and the
/// shell their forced `script-shell` names: the host's, on the sandbox's
/// read-only system roots (tog provisions neither).
pub(crate) const HOST_GIT: &str = "/usr/bin/git";
pub(crate) const HOST_SH: &str = "/bin/sh";

/// Which tool a run starts.
pub(crate) enum NodeTool<'a> {
    /// The store Node's npm.
    Npm { node_obj: &'a Path },
    /// The pinned pnpm, run as `node <script>` from the environment object
    /// `tog x` realized it into ([`pnpm_program`]).
    Pnpm {
        node_obj: &'a Path,
        program: &'a PnpmProgram,
    },
}

impl NodeTool<'_> {
    fn name(&self) -> &'static str {
        match self {
            NodeTool::Npm { .. } => "npm",
            NodeTool::Pnpm { .. } => "pnpm",
        }
    }
}

/// One confined run of npm or pnpm.
pub(crate) struct NodeRun<'a> {
    pub tool: NodeTool<'a>,
    /// Where the lock lives: the project, or the pnpm workspace root.
    pub lock_root: &'a Path,
    /// The directory the tool runs in, relative to the lock root (a pnpm
    /// workspace member); `None` is the lock root.
    pub cwd: Option<PathBuf>,
    /// The verb and its arguments.
    pub args: Vec<String>,
    pub publish: Publish<'a>,
    /// Capture the tool's output into the report instead of letting the
    /// user watch it.
    pub capture: bool,
}

/// The pinned pnpm as `tog x` realized it: the store environment object
/// its cache root links into, and the script `node` runs.
pub(crate) struct PnpmProgram {
    pub env_obj: PathBuf,
    pub script: PathBuf,
}

/// Find the pnpm in the `tog x` cache root `root`: the environment object
/// its closure names, and `node_modules/pnpm`'s `bin` script in it. The
/// sandbox mounts the object, not the cache root, so the script is named
/// by its path in the object.
pub(crate) fn pnpm_program(root: &Path, version: &str) -> io::Result<PnpmProgram> {
    let closure = crate::comforter::read_closure(root, "node")?;
    let env_obj = closure["env_object"]
        .as_str()
        .map(PathBuf::from)
        .ok_or_else(|| io::Error::other("the pnpm cache's node closure names no env_object"))?;
    let package_dir = env_obj.join("node_modules/pnpm");
    let manifest_path = package_dir.join("package.json");
    let manifest: serde_json::Value = serde_json::from_slice(&std::fs::read(&manifest_path)?)
        .map_err(|error| io::Error::other(format!("{}: {error}", manifest_path.display())))?;
    if manifest["version"].as_str() != Some(version) {
        return Err(io::Error::other(format!(
            "{} is pnpm {}, not the pinned {version}",
            manifest_path.display(),
            manifest["version"].as_str().unwrap_or("?")
        )));
    }
    let bin = manifest["bin"]["pnpm"].as_str().ok_or_else(|| {
        io::Error::other(format!("{} names no pnpm bin", manifest_path.display()))
    })?;
    let plain = Path::new(bin)
        .components()
        .all(|component| matches!(component, Component::Normal(_)));
    if !plain {
        return Err(io::Error::other(format!(
            "{} names the pnpm bin {bin:?}, which is not a plain path",
            manifest_path.display()
        )));
    }
    let script = package_dir.join(bin);
    if !script.is_file() {
        return Err(io::Error::other(format!(
            "store pnpm@{version} has no {} script",
            script.display()
        )));
    }
    Ok(PnpmProgram { env_obj, script })
}

/// The npm a resolution record names: the one bundled in the store Node.
pub(crate) fn npm_tool(node_obj: &Path) -> io::Result<record::Tool> {
    let manifest_path = node_obj.join("lib/node_modules/npm/package.json");
    let manifest: serde_json::Value = serde_json::from_slice(&std::fs::read(&manifest_path)?)
        .map_err(|error| io::Error::other(format!("{}: {error}", manifest_path.display())))?;
    let version = manifest["version"]
        .as_str()
        .ok_or_else(|| io::Error::other(format!("{} has no version", manifest_path.display())))?;
    Ok(record::Tool {
        name: "npm".to_string(),
        version: version.to_string(),
    })
}

/// The pnpm a resolution record names: the pinned release.
pub(crate) fn pnpm_tool(version: &str) -> record::Tool {
    record::Tool {
        name: "pnpm".to_string(),
        version: version.to_string(),
    }
}

/// The tool invocation of `run`: the store npm, or the store node running
/// the pinned pnpm's script, in the lock root, with `PATH` naming the
/// store Node and the system's own tools (the git npm starts).
fn node_spec(run: &NodeRun<'_>) -> DelegateSpec {
    let (node_obj, mut spec) = match &run.tool {
        NodeTool::Npm { node_obj } => (*node_obj, DelegateSpec::new(node_obj.join("bin/npm"))),
        NodeTool::Pnpm { node_obj, program } => {
            let mut spec = DelegateSpec::new(node_obj.join("bin/node"));
            spec.arg(&program.script);
            (*node_obj, spec)
        }
    };
    spec.args(&run.args).lock_root(run.lock_root).env(
        "PATH",
        format!("{}:/usr/bin:/bin", node_obj.join("bin").display()),
    );
    if let NodeTool::Pnpm { .. } = run.tool {
        // The one way to say "run no lifecycle script" that every pnpm
        // verb reads, beside the forced flag; `CI` keeps pnpm from any
        // interactive prompt.
        spec.env("CI", "1").env("npm_config_ignore_scripts", "true");
    }
    if run.capture {
        spec.capture();
    }
    spec
}

/// The `ConfinedSpec` of `run`, through the process proxy with TLS
/// interception on the npm route. Tests replace the proxy and the
/// permitted set.
pub(crate) fn node_confined<'a>(
    run: &NodeRun<'a>,
    publish: Publish<'a>,
) -> io::Result<ConfinedSpec<'a>> {
    for program in [HOST_GIT, HOST_SH] {
        if !Path::new(program).is_file() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "{} resolves with {program} as its forced git or shell, which this host \
                     does not have",
                    run.tool.name()
                ),
            ));
        }
    }
    let (tool, why) = match &run.tool {
        NodeTool::Npm { .. } => ("npm", WHY_NPM),
        NodeTool::Pnpm { .. } => ("pnpm", WHY_PNPM),
    };
    let mut confined = ConfinedSpec::new("node", tool, why);
    confined.forced.git = Some(Path::new(HOST_GIT));
    confined.forced.sh = Some(Path::new(HOST_SH));
    confined.store_reads = match &run.tool {
        NodeTool::Npm { node_obj } => vec![node_obj.to_path_buf()],
        NodeTool::Pnpm { node_obj, program } => {
            vec![node_obj.to_path_buf(), program.env_obj.clone()]
        }
    };
    // An installed tree is never a resolution input: npm's lock-only
    // install ignores it, and pnpm's modules state is pointed into the
    // scratch. Tog's projection is a symlink into the store anyway.
    confined.exclude = vec![PathGlob::new("**/node_modules")?];
    confined.routes = vec![registry::route()?];
    confined.intercept = Intercept::Tls;
    confined.cwd = run.cwd.clone();
    let kind = match &run.tool {
        NodeTool::Npm { .. } => Kind::Npm,
        NodeTool::Pnpm { .. } => Kind::Pnpm,
    };
    let project = match &run.cwd {
        Some(cwd) => run.lock_root.join(cwd),
        None => run.lock_root.to_path_buf(),
    };
    let lock_root = run.lock_root.to_path_buf();
    confined.wire = Some(Box::new(move |wire: &Wire<'_>| {
        wiring(kind, wire, &lock_root, &project)
    }));
    confined.publish(publish);
    Ok(confined)
}

#[derive(Clone, Copy)]
enum Kind {
    Npm,
    Pnpm,
}

/// The session settings before the verb, the forced ones among them, and
/// the environment any other Node code reads.
fn wiring(kind: Kind, wire: &Wire<'_>, lock_root: &Path, project: &Path) -> io::Result<Wiring> {
    let ca_file = wire.ca_file.ok_or_else(|| {
        io::Error::other("npm and pnpm resolve only through TLS interception, which this run lacks")
    })?;
    let proxy = wire.address.proxy_url();
    let ca = ca_file.to_string_lossy();
    // pnpm runs as `node <script> ...`: the settings follow the script,
    // where pnpm reads them, not node.
    let (program_args, tool_args) = match kind {
        Kind::Npm => (&wire.args[..0], wire.args),
        Kind::Pnpm => wire.args.split_at(1.min(wire.args.len())),
    };
    let mut args: Vec<OsString> = program_args.to_vec();
    match kind {
        Kind::Npm => {
            args.extend(
                [
                    format!("--proxy={proxy}"),
                    format!("--https-proxy={proxy}"),
                    "--noproxy=".to_string(),
                    format!("--registry={}", registry::REGISTRY_URL),
                    "--strict-ssl=true".to_string(),
                    format!("--cafile={ca}"),
                    "--update-notifier=false".to_string(),
                    "--audit=false".to_string(),
                    "--fund=false".to_string(),
                    format!("--cache={}", wire.scratch.join("npm-cache").display()),
                ]
                .into_iter()
                .map(OsString::from),
            );
        }
        Kind::Pnpm => {
            let scratch = PnpmScratch::new(wire.scratch, project, lock_root);
            args.extend(
                [
                    format!("--config.proxy={proxy}"),
                    format!("--config.https-proxy={proxy}"),
                    "--config.noproxy=".to_string(),
                    format!("--config.registry={}", registry::REGISTRY_URL),
                    "--config.strict-ssl=true".to_string(),
                    format!("--config.cafile={ca}"),
                    "--config.update-notifier=false".to_string(),
                    "--config.enable-modules-dir=false".to_string(),
                    "--config.node-linker=isolated".to_string(),
                    format!("--config.modules-dir={}", scratch.modules_dir),
                    format!("--config.virtual-store-dir={}", scratch.virtual_store_dir),
                    format!("--config.store-dir={}", scratch.store_dir),
                    format!("--config.cache-dir={}", scratch.cache_dir),
                ]
                .into_iter()
                .map(OsString::from),
            );
        }
    }
    args.extend(wire.forced_args.iter().cloned());
    args.extend(tool_args.iter().cloned());
    let mut env: Vec<(OsString, OsString)> = vec![
        (
            "NODE_EXTRA_CA_CERTS".into(),
            ca_file.as_os_str().to_os_string(),
        ),
        ("NPM_CONFIG_AUDIT".into(), "false".into()),
        ("NPM_CONFIG_FUND".into(), "false".into()),
        ("NPM_CONFIG_UPDATE_NOTIFIER".into(), "false".into()),
    ];
    env.extend(door::proxy_env(wire.address, ca_file));
    Ok(Wiring {
        args,
        env,
        ..Wiring::default()
    })
}

/// Where pnpm keeps its modules state and store during a run: the scratch,
/// never the project.
///
/// Even with `--lockfile-only`, pnpm's modules directory is live: at a
/// workspace root `add -w --lockfile-only` performs a full install, every
/// verb reads `node_modules/.modules.yaml` and refuses with
/// `ERR_PNPM_UNEXPECTED_STORE` when the store recorded there is not the one
/// it is given, and the workspace path deletes `<virtual-store-dir>/lock.yaml`
/// when the current lockfile is empty. `enable-modules-dir=false` links
/// nothing, `modules-dir` decides where `.modules.yaml` is looked for, and
/// `virtual-store-dir` decides where the current lockfile lives. pnpm joins
/// both onto a project directory (`path.join`, so an absolute value would
/// land inside the project), hence the relative spellings; the store and
/// cache directories are resolved against the cwd, so they are absolute.
struct PnpmScratch {
    /// `--config.modules-dir`, relative to the project pnpm runs in. pnpm
    /// joins it onto every importer's own directory, so what keeps the
    /// snapshot untouched is `enable-modules-dir=false` with
    /// `node-linker=isolated`, under which pnpm creates no importer
    /// `node_modules` at all; this path only names a `.modules.yaml` to
    /// read.
    modules_dir: String,
    /// `--config.virtual-store-dir`, relative to the lock root.
    virtual_store_dir: String,
    store_dir: String,
    cache_dir: String,
}

impl PnpmScratch {
    fn new(scratch: &Path, project: &Path, lock_root: &Path) -> Self {
        let modules = scratch.join("pnpm/modules");
        PnpmScratch {
            modules_dir: relative_path(project, &modules)
                .to_string_lossy()
                .into_owned(),
            virtual_store_dir: relative_path(lock_root, &modules.join(".pnpm"))
                .to_string_lossy()
                .into_owned(),
            store_dir: scratch.join("pnpm/store").to_string_lossy().into_owned(),
            cache_dir: scratch.join("pnpm/cache").to_string_lossy().into_owned(),
        }
    }
}

/// `to` expressed relative to the directory `from`; both absolute and
/// free of `..` (the lock root is canonical, the scratch is a stage path),
/// so the answer is a lexical prefix strip.
fn relative_path(from: &Path, to: &Path) -> PathBuf {
    let from: Vec<_> = from.components().collect();
    let to: Vec<_> = to.components().collect();
    let common = from
        .iter()
        .zip(to.iter())
        .take_while(|(a, b)| a == b)
        .count();
    let mut out = PathBuf::new();
    for _ in common..from.len() {
        out.push("..");
    }
    for component in &to[common..] {
        out.push(component);
    }
    out
}

/// Run npm or pnpm confined through `door`. A Detached run's ledger ids
/// come back in the report for the caller to root.
pub(crate) fn run_node(
    door: &mut ResolutionDoor<'_>,
    mut run: NodeRun<'_>,
) -> io::Result<DelegateReport> {
    let publish = std::mem::replace(
        &mut run.publish,
        Publish::Detached {
            outputs: Vec::new(),
        },
    );
    let confined = node_confined(&run, publish)?;
    let spec = node_spec(&run);
    spec.trace();
    let name = run.tool.name();
    door.run_confined(spec, confined).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("store {name} {}: {error}", run.args.join(" ")),
        )
    })
}

/// `run_node` that fails on a nonzero exit, naming the tool's own words
/// when they were captured.
pub(crate) fn run_node_checked(
    door: &mut ResolutionDoor<'_>,
    run: NodeRun<'_>,
) -> io::Result<DelegateReport> {
    let name = run.tool.name();
    let args = run.args.join(" ");
    let report = run_node(door, run)?;
    if !report.status.success() {
        let words = confine::scrub_signing_key(String::from_utf8_lossy(&report.stderr).trim());
        return Err(io::Error::other(if words.is_empty() {
            format!(
                "store {name} {args} failed (exit status {}); nothing was synced",
                report.status
            )
        } else {
            format!("store {name} {args} failed: {words}")
        }));
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::testutil::TempDir;
    use std::fs;

    /// Lexically resolve `base/relative` (`..` pops), the way pnpm's
    /// `path.join` does, to check where a relative setting lands.
    fn lexical_join(base: &Path, relative: &str) -> PathBuf {
        let mut out = base.to_path_buf();
        for component in Path::new(relative).components() {
            match component {
                Component::ParentDir => {
                    out.pop();
                }
                Component::Normal(name) => out.push(name),
                _ => {}
            }
        }
        out
    }

    /// pnpm joins `modules-dir` onto every importer's directory and
    /// `virtual-store-dir` onto the lock root. From the project pnpm runs
    /// in both land in the run's scratch, and from any shallower importer
    /// the modules dir still escapes the project tree. A root-computed one
    /// lands back inside the project for a deeper importer; the linker
    /// flags, not this path, are what keep that harmless.
    #[test]
    fn pnpm_scratch_paths_resolve_where_pnpm_joins_them() {
        let temp = TempDir::named("pnpm-scratch");
        let scratch = temp.0.join("store/tmp/stage-1");
        let lock_root = temp.0.join("proj");
        let member = lock_root.join("packages/lib");
        fs::create_dir_all(&scratch).unwrap();
        fs::create_dir_all(&member).unwrap();
        let scratch_c = scratch.canonicalize().unwrap();
        let lock_root_c = lock_root.canonicalize().unwrap();
        let member_c = member.canonicalize().unwrap();

        let paths = PnpmScratch::new(&scratch_c, &member_c, &lock_root_c);
        assert!(!paths.modules_dir.starts_with('/'), "{}", paths.modules_dir);
        assert!(
            !paths.virtual_store_dir.starts_with('/'),
            "{}",
            paths.virtual_store_dir
        );
        assert_eq!(
            lexical_join(&member_c, &paths.modules_dir),
            scratch_c.join("pnpm/modules")
        );
        assert_eq!(
            lexical_join(&lock_root_c, &paths.virtual_store_dir),
            scratch_c.join("pnpm/modules/.pnpm")
        );
        // The root importer joins the same modules-dir onto its own path.
        let from_root = lexical_join(&lock_root_c, &paths.modules_dir);
        assert!(
            !from_root.starts_with(&lock_root_c),
            "root importer's modules dir {} is inside the project",
            from_root.display()
        );
        assert_eq!(
            paths.store_dir,
            scratch_c.join("pnpm/store").display().to_string()
        );
        assert_eq!(
            paths.cache_dir,
            scratch_c.join("pnpm/cache").display().to_string()
        );

        let paths = PnpmScratch::new(&scratch_c, &lock_root_c, &lock_root_c);
        assert_eq!(
            lexical_join(&lock_root_c, &paths.modules_dir),
            scratch_c.join("pnpm/modules")
        );
        // A root-computed modules-dir lands INSIDE the project for a deeper
        // importer: a property of `path.join` and one relative path, not
        // something to fix by computing it differently. Safety comes from
        // `enable-modules-dir=false` with `node-linker=isolated`, and
        // `deps_e2e::pnpm_edits_leave_an_installed_project_untouched` is
        // what proves it end to end.
        let from_member = lexical_join(&member_c, &paths.modules_dir);
        assert!(
            from_member.starts_with(&lock_root_c),
            "expected the documented in-project landing, got {}",
            from_member.display()
        );
        assert_eq!(
            relative_path(Path::new("/a/b/c"), Path::new("/a/x/y")),
            PathBuf::from("../../x/y")
        );
        assert_eq!(
            relative_path(Path::new("/a"), Path::new("/a/x")),
            PathBuf::from("x")
        );
    }

    use crate::kernel::platform::Platform;
    use crate::kernel::policy::{self, Attribution, Exception, Policy};
    use crate::kernel::resolve::door::{PROXY_FOR_TEST, RELAY_FOR_TEST, SKIP_SCAN_FOR_TEST};
    use crate::kernel::resolve::ledger::{self, Entry};
    use crate::kernel::resolve::testing::{
        blind_forwarder, relay, stored_rows, Harness, Reach, TEST_ORIGIN_PUBLIC,
    };
    use crate::kernel::resolve::{DelegateReport, DoorKind, ResolutionDoor};
    use crate::kernel::testutil::upstream::{Behavior, Reply};
    use crate::tailors::edit::{CachedTool, EditHost};
    use crate::tailors::node::resolve::npm_resolve_args;
    use std::os::unix::fs::PermissionsExt;

    const NPM_HOSTS: &[&str] = &[
        registry::REGISTRY_HOST,
        "github.com",
        "tarballs.test",
        "evil.test",
    ];

    /// A harness whose upstream answers for the registry and the hosts the
    /// tests send the tools to, from the recorded `registry` rows, and
    /// whose proxy the process uses while the harness lives (the x cache's
    /// realization, which needs the real registry, switches it off).
    fn node_harness(label: &str, registry: &str) -> Option<&'static Harness> {
        let relay = relay(label)?;
        RELAY_FOR_TEST.with(|slot| *slot.borrow_mut() = Some(relay));
        SKIP_SCAN_FOR_TEST.with(|skip| skip.set(true));
        let mut reach = Reach::public(|_, _| vec![TEST_ORIGIN_PUBLIC.parse().unwrap()]);
        reach.request_timeout = std::time::Duration::from_secs(10);
        let rows = stored_rows(registry, label);
        let harness: &'static Harness = Box::leak(Box::new(Harness::serving(
            label,
            reach,
            NPM_HOSTS,
            &rows.0.to_string_lossy(),
        )));
        std::mem::forget(rows);
        PROXY_FOR_TEST.with(|slot| slot.set(Some(&harness.proxy)));
        Some(harness)
    }

    fn done() {
        RELAY_FOR_TEST.with(|slot| *slot.borrow_mut() = None);
        PROXY_FOR_TEST.with(|slot| slot.set(None));
    }

    /// The store Node realized in the harness's store, over the network.
    fn store_node(harness: &Harness) -> PathBuf {
        let selected = crate::tailors::node::shipped_selection().unwrap();
        super::super::realize_runtime(
            &harness.store,
            &harness.activity,
            Platform::host().unwrap(),
            &selected,
        )
        .unwrap()
    }

    /// A project in `dir` with `dependencies` (a JSON object body).
    fn project(dir: &Path, dependencies: &str) -> PathBuf {
        fs::create_dir_all(dir).unwrap();
        fs::write(
            dir.join("package.json"),
            format!("{{\n  \"name\": \"spike\",\n  \"version\": \"1.0.0\",\n  \"dependencies\": {{{dependencies}}}\n}}\n"),
        )
        .unwrap();
        dir.canonicalize().unwrap()
    }

    /// `run` through a door of `kind` on the harness proxy, under `policy`.
    fn through_door(
        harness: &Harness,
        kind: DoorKind,
        policy: Policy,
        run: NodeRun<'_>,
    ) -> (io::Result<DelegateReport>, Vec<Exception>) {
        let mut attribution = Attribution::open("node").unwrap();
        let mut door = ResolutionDoor::open(
            &harness.store,
            &harness.activity,
            Platform::host().unwrap(),
            kind,
            &mut attribution,
        )
        .unwrap();
        let mut run = run;
        let publish = std::mem::replace(
            &mut run.publish,
            Publish::Detached {
                outputs: Vec::new(),
            },
        );
        let mut confined = node_confined(&run, publish).unwrap();
        confined.proxy = Some(&harness.proxy);
        confined.policy = Some(policy);
        let spec = node_spec(&run);
        let report = door.run_confined(spec, confined);
        drop(door);
        let recorded = attribution.recorded();
        attribution.discard();
        (report, recorded)
    }

    fn lock_only_run<'a>(node_obj: &'a Path, project: &'a Path) -> NodeRun<'a> {
        NodeRun {
            tool: NodeTool::Npm { node_obj },
            lock_root: project,
            cwd: None,
            args: npm_resolve_args("install", &[]),
            publish: Publish::Project {
                outputs: vec![
                    PathBuf::from("package.json"),
                    PathBuf::from("package-lock.json"),
                ],
                receipt: None,
            },
            capture: true,
        }
    }

    fn ledger_entries(harness: &Harness, report: &DelegateReport) -> Vec<Entry> {
        let objects = report.ledger.as_ref().expect("a ledger");
        let portable = ledger::PortableLedger::parse(
            &ledger::read_portable(&harness.store, &objects.ledger).unwrap(),
        )
        .unwrap();
        portable.entries().cloned().collect()
    }

    fn stderr(report: &DelegateReport) -> String {
        String::from_utf8_lossy(&report.stderr).into_owned()
    }

    /// Every flag a tool run gets, and nothing of the environment tog runs
    /// in: a stand-in Node object whose `npm` writes its argv and
    /// environment into the lock it is asked for, run through the
    /// missing-lock door. The session's flags, the forced settings, and
    /// the quiet settings are all there; the environment holds the proxy,
    /// the CA, and the home in the scratch; and the door publishes the lock
    /// with a resolution record.
    #[test]
    fn npm_runs_with_the_session_and_forced_flags_only() {
        let _serial = policy::attribution_test_lock();
        let Some(harness) = node_harness("npm_runs_with_the_session_and_forced_flags_only", "npm")
        else {
            return;
        };
        let platform = Platform::host().unwrap();
        let selected = crate::tailors::node::shipped_selection().unwrap();
        let staged = harness.store.stage().unwrap();
        for file in [
            "bin/node",
            "include/node/node.h",
            "lib/node_modules/npm/bin/npm-cli.js",
            "lib/node_modules/npm/node_modules/node-gyp/bin/node-gyp.js",
        ] {
            fs::create_dir_all(staged.join(file).parent().unwrap()).unwrap();
            fs::write(staged.join(file), "").unwrap();
        }
        fs::write(
            staged.join("lib/node_modules/npm/package.json"),
            r#"{"name":"npm","version":"0.0.0-stand-in"}"#,
        )
        .unwrap();
        let npm = staged.join("bin/npm");
        fs::write(
            &npm,
            "#!/bin/sh\n{ printf '%s\\n' \"$@\"; echo '---env---'; env | sort; echo \"---cwd---\"; pwd; } \
             | sed -e 's/tog:[0-9a-f]*@/tog:TOKEN@/g' -e 's/127\\.0\\.0\\.1:8119/PROXY/g' \
             > package-lock.json\n",
        )
        .unwrap();
        fs::set_permissions(&npm, fs::Permissions::from_mode(0o755)).unwrap();
        crate::tailors::install_kinds();
        harness
            .store
            .commit_with_deps(
                &crate::tailors::node::runtime_identity(&selected, platform).unwrap(),
                &staged,
                &[],
                &crate::kernel::store::ObjectDeps::new(),
            )
            .unwrap();
        let temp = TempDir::named("npm-stand-in");
        let project_dir = project(&temp.0.join("project"), "");
        fs::write(
            project_dir.join(".npmrc"),
            "registry=https://evil.test/\naudit=true\nfund=true\nupdate-notifier=true\n",
        )
        .unwrap();
        let held = crate::kernel::fsroot::ProjectRoot::open(&project_dir).unwrap();
        let mut attribution = Attribution::open("node").unwrap();
        let mut door = ResolutionDoor::open(
            &harness.store,
            &harness.activity,
            platform,
            DoorKind::MissingLock,
            &mut attribution,
        )
        .unwrap();
        crate::tailors::node::resolve::generate_lock(&mut door, &held, &selected).unwrap();
        drop(door);
        let recorded = attribution.recorded();
        attribution.discard();
        done();
        assert!(recorded.is_empty(), "{recorded:?}");
        let lock = fs::read_to_string(project_dir.join("package-lock.json")).unwrap();
        let (args, rest) = lock.split_once("---env---\n").unwrap();
        let (env, cwd) = rest.split_once("---cwd---\n").unwrap();
        let args: Vec<&str> = args.lines().collect();
        for flag in [
            "--proxy=http://tog:TOKEN@PROXY",
            "--https-proxy=http://tog:TOKEN@PROXY",
            "--noproxy=",
            "--registry=https://registry.npmjs.org/",
            "--strict-ssl=true",
            "--cafile=/run/tog/ca.pem",
            "--update-notifier=false",
            "--audit=false",
            "--fund=false",
            "--git=/usr/bin/git",
            "--script-shell=/bin/sh",
            "--shell=/bin/sh",
            "--ignore-scripts",
            "--node-options=",
            "--node-gyp=/nonexistent/node-gyp",
            "--editor=false",
            "--browser=false",
            "--viewer=false",
            "install",
            "--package-lock-only",
            "--no-audit",
            "--no-fund",
            "--no-update-notifier",
        ] {
            assert!(args.contains(&flag), "{flag} missing from {args:?}");
        }
        assert!(
            args.iter().any(|arg| arg.starts_with("--cache=")),
            "{args:?}"
        );
        let has = |line: &str| env.lines().any(|found| found == line);
        for line in [
            "NODE_EXTRA_CA_CERTS=/run/tog/ca.pem",
            "NPM_CONFIG_AUDIT=false",
            "NPM_CONFIG_FUND=false",
            "NPM_CONFIG_UPDATE_NOTIFIER=false",
            "HTTPS_PROXY=http://tog:TOKEN@PROXY",
            "https_proxy=http://tog:TOKEN@PROXY",
            "NO_PROXY=",
            "SSL_CERT_FILE=/run/tog/ca.pem",
            "GIT_CONFIG_NOSYSTEM=1",
        ] {
            assert!(has(line), "{line} missing from {env}");
        }
        assert!(
            !env.lines().any(|line| line.starts_with("NODE_OPTIONS=")),
            "{env}"
        );
        assert!(
            env.lines().any(|line| line.starts_with("GIT_CONFIG_VALUE_")
                && line.ends_with("=http://tog:TOKEN@PROXY")),
            "the git row carries the proxy: {env}"
        );
        assert!(
            !env.lines().any(|line| line.starts_with("HOME=")
                && line.contains(&project_dir.display().to_string())),
            "{env}"
        );
        assert_eq!(cwd.trim(), project_dir.display().to_string());
        let receipt = fs::read_to_string(project_dir.join(".tog/resolution/node.json")).unwrap();
        assert!(
            receipt.contains("\"package-lock.json\"") && receipt.contains("\"package.json\""),
            "{receipt}"
        );
        assert!(receipt.contains("\".npmrc\""), "{receipt}");
        assert!(harness.upstream.seen().is_empty());
    }

    /// `npm install --package-lock-only` confined, its registry traffic
    /// intercepted and answered by the recorded registry: the lock records
    /// the registry's own tarball URLs and integrity, every request went to
    /// the registry through the route, and none was an audit, a funding
    /// lookup, or the update notifier, whatever the project's `.npmrc`
    /// says (its registry, audit, fund and notifier settings, and a proxy
    /// and CA of its own, are all beaten by the door's flags).
    ///
    /// Ignored: it realizes the store Node over the network. The
    /// resolution itself is offline.
    #[test]
    #[ignore = "realizes the store Node over the network"]
    fn npm_resolution_makes_only_registry_requests() {
        let _serial = policy::attribution_test_lock();
        let Some(harness) = node_harness("npm_resolution_makes_only_registry_requests", "npm")
        else {
            return;
        };
        let node_obj = store_node(harness);
        let temp = TempDir::named("npm-only-registry");
        let project_dir = project(&temp.0.join("project"), "\"is-odd\": \"3.0.1\"");
        fs::write(
            project_dir.join(".npmrc"),
            "registry=https://evil.test/\naudit=true\nfund=true\nupdate-notifier=true\n\
             proxy=http://127.0.0.1:1/\nhttps-proxy=http://127.0.0.1:1/\n\
             cafile=/nonexistent/ca.pem\nstrict-ssl=false\nignore-scripts=false\n",
        )
        .unwrap();
        let (report, recorded) = through_door(
            harness,
            DoorKind::MissingLock,
            Policy::default(),
            lock_only_run(&node_obj, &project_dir),
        );
        done();
        let report = report.unwrap();
        assert!(report.status.success(), "{}", stderr(&report));
        assert!(recorded.is_empty(), "{recorded:?}");
        let lock = fs::read_to_string(project_dir.join("package-lock.json")).unwrap();
        assert!(
            lock.contains("\"resolved\": \"https://registry.npmjs.org/is-odd/-/is-odd-3.0.1.tgz\"")
                && lock.contains("\"integrity\": \"sha512-"),
            "{lock}"
        );
        let entries = ledger_entries(harness, &report);
        assert!(
            entries.iter().any(|entry| entry.class == "metadata"
                && entry.url == "https://registry.npmjs.org/is-odd"
                && entry.status == 200),
            "{entries:?}"
        );
        assert!(
            entries
                .iter()
                .all(|entry| entry.url.starts_with("https://registry.npmjs.org/")),
            "{entries:?}"
        );
        assert!(
            entries.iter().all(|entry| !entry.url.contains("/-/npm/")
                && entry.url != "https://registry.npmjs.org/npm"),
            "an audit, funding or notifier request: {entries:?}"
        );
        assert!(harness.upstream.seen().iter().all(|seen| {
            seen.sni.as_deref() == Some(registry::REGISTRY_HOST)
                && seen.headers.get("proxy-authorization").is_none()
        }));
    }

    /// Contract 8: the lock npm writes through interception is
    /// byte-identical to the one the same npm writes reaching the same
    /// registry directly (through a forwarder that never looks inside the
    /// tunnel, trusting the registry's own certificate).
    #[test]
    #[ignore = "realizes the store Node over the network"]
    fn npm_add_through_interception_lock_matches_direct_run() {
        let _serial = policy::attribution_test_lock();
        let Some(harness) = node_harness(
            "npm_add_through_interception_lock_matches_direct_run",
            "npm",
        ) else {
            return;
        };
        let node_obj = store_node(harness);
        let temp = TempDir::named("npm-lock-identical");
        let intercepted = project(&temp.0.join("intercepted"), "");
        let direct = project(&temp.0.join("direct"), "");
        let mut run = lock_only_run(&node_obj, &intercepted);
        run.args = npm_resolve_args("install", &[]);
        run.args
            .extend(["--".to_string(), "is-odd@3.0.1".to_string()]);
        let (report, _) = through_door(harness, DoorKind::Edit, Policy::default(), run);
        done();
        let report = report.unwrap();
        assert!(report.status.success(), "{}", stderr(&report));

        let forwarder = blind_forwarder(harness.upstream.address());
        let ca = temp.0.join("fixture-ca.pem");
        fs::write(&ca, harness.upstream_ca_pem()).unwrap();
        let home = temp.0.join("home");
        fs::create_dir_all(&home).unwrap();
        let output = std::process::Command::new(node_obj.join("bin/npm"))
            .args([
                &format!("--proxy=http://{forwarder}"),
                &format!("--https-proxy=http://{forwarder}"),
                "--noproxy=",
                "--registry=https://registry.npmjs.org/",
                "--strict-ssl=true",
                &format!("--cafile={}", ca.display()),
                "--update-notifier=false",
                "--audit=false",
                "--fund=false",
                &format!("--cache={}", temp.0.join("npm-cache").display()),
                "--silent",
                "install",
                "--package-lock-only",
                "--ignore-scripts",
                "--",
                "is-odd@3.0.1",
            ])
            .current_dir(&direct)
            .env_clear()
            .env(
                "PATH",
                format!("{}:/usr/bin:/bin", node_obj.join("bin").display()),
            )
            .env("HOME", &home)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let through = fs::read_to_string(intercepted.join("package-lock.json")).unwrap();
        assert_eq!(
            through,
            fs::read_to_string(direct.join("package-lock.json")).unwrap()
        );
        assert!(through.contains("https://registry.npmjs.org/is-odd/-/is-odd-3.0.1.tgz"));
        assert_eq!(
            fs::read_to_string(intercepted.join("package.json")).unwrap(),
            fs::read_to_string(direct.join("package.json")).unwrap()
        );
    }

    /// A dependency named by a tarball URL on another host is fetched
    /// through interception, recorded as `unattested-index` naming the
    /// host, and the lock records the URL as npm resolved it. With the
    /// kind denied the request is refused, the door fails, and the project
    /// is untouched.
    #[test]
    #[ignore = "realizes the store Node over the network"]
    fn npm_url_dependency_is_intercepted_and_recorded() {
        let _serial = policy::attribution_test_lock();
        let Some(harness) = node_harness("npm_url_dependency_is_intercepted_and_recorded", "npm")
        else {
            return;
        };
        let tarball = fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join(
            "tests/fixtures/proxy/registry/npm/registry.npmjs.org/is-odd/-/is-odd-3.0.1.tgz.body",
        ))
        .unwrap();
        harness.upstream.set(
            "/is-odd-3.0.1.tgz",
            Behavior::Reply(
                Reply::new(200, &tarball).header("Content-Type", "application/octet-stream"),
            ),
        );
        let node_obj = store_node(harness);
        let temp = TempDir::named("npm-url-dep");
        let project_dir = project(
            &temp.0.join("project"),
            "\"is-odd\": \"https://tarballs.test/is-odd-3.0.1.tgz\"",
        );
        let (report, recorded) = through_door(
            harness,
            DoorKind::MissingLock,
            Policy::default(),
            lock_only_run(&node_obj, &project_dir),
        );
        let report = report.unwrap();
        assert!(report.status.success(), "{}", stderr(&report));
        assert_eq!(recorded.len(), 1, "{recorded:?}");
        assert_eq!(recorded[0].kind, policy::UNATTESTED_INDEX);
        assert_eq!(recorded[0].subject, "https://tarballs.test");
        let lock = fs::read_to_string(project_dir.join("package-lock.json")).unwrap();
        assert!(
            lock.contains("\"resolved\": \"https://tarballs.test/is-odd-3.0.1.tgz\""),
            "{lock}"
        );
        let entries = ledger_entries(harness, &report);
        assert!(
            entries.iter().any(
                |entry| entry.url == "https://tarballs.test/is-odd-3.0.1.tgz"
                    && entry.status == 200
            ),
            "{entries:?}"
        );

        let denied = Policy {
            deny: [policy::UNATTESTED_INDEX.to_string()].into(),
            ..Policy::default()
        };
        let refused_dir = project(
            &temp.0.join("refused"),
            "\"is-odd\": \"https://tarballs.test/is-odd-3.0.1.tgz\"",
        );
        let (report, recorded) = through_door(
            harness,
            DoorKind::MissingLock,
            denied,
            lock_only_run(&node_obj, &refused_dir),
        );
        done();
        let error = report.unwrap_err().to_string();
        assert!(error.contains("unattested-index"), "{error}");
        assert!(recorded.is_empty(), "{recorded:?}");
        assert!(!refused_dir.join("package-lock.json").exists());
    }

    /// The project's `.npmrc` names a marker program for every
    /// program-naming setting npm has (`git`, `script-shell`, `shell`,
    /// `node-gyp`, `editor`, `browser`, `viewer`, `node-options`), and a git
    /// dependency with a `prepare` script, and none runs: the lock-only
    /// install clones the dependency with the forced git and leaves the
    /// script alone. A marker that ran would write into the project, which
    /// the door would refuse as an undeclared change.
    #[test]
    #[ignore = "realizes the store Node over the network"]
    fn npm_forced_settings_never_run_the_project_git_or_script_shell() {
        let _serial = policy::attribution_test_lock();
        let label = "npm_forced_settings_never_run_the_project_git_or_script_shell";
        let Some(harness) = node_harness(label, "npm") else {
            return;
        };
        let node_obj = store_node(harness);
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/proxy/forced/npm");
        let settings: serde_json::Value =
            serde_json::from_slice(&fs::read(fixture.join("settings.json")).unwrap()).unwrap();
        let temp = TempDir::named("npm-forced");
        let project_dir = temp.0.join("project");
        fs::create_dir_all(project_dir.join("markers")).unwrap();
        fs::create_dir_all(project_dir.join("hit")).unwrap();
        let project_dir = project_dir.canonicalize().unwrap();
        let hit = project_dir.join("hit");
        // The git dependency: a repository inside the project with a
        // `prepare` script that records when it runs.
        let repo = project_dir.join("prepdep.repo");
        fs::create_dir_all(&repo).unwrap();
        fs::write(
            repo.join("package.json"),
            fs::read_to_string(fixture.join("prepdep/package.json"))
                .unwrap()
                .replace("@HIT@", &hit.display().to_string()),
        )
        .unwrap();
        let git = |args: &[&str]| {
            let output = std::process::Command::new("git")
                .args(args)
                .current_dir(&repo)
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_AUTHOR_NAME", "t")
                .env("GIT_AUTHOR_EMAIL", "t@t")
                .env("GIT_COMMITTER_NAME", "t")
                .env("GIT_COMMITTER_EMAIL", "t@t")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "git {args:?}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        };
        git(&["init", "-q", "-b", "main"]);
        git(&["add", "."]);
        git(&["commit", "-q", "-m", "prepdep"]);
        fs::write(
            project_dir.join("package.json"),
            fs::read_to_string(fixture.join("package.json"))
                .unwrap()
                .replace("@SCENARIO@", &project_dir.display().to_string()),
        )
        .unwrap();
        let mut npmrc = String::new();
        for setting in settings["settings"].as_array().unwrap() {
            let name = setting["name"].as_str().unwrap();
            let line = setting["line"].as_str().unwrap();
            let shell = project_dir.join("markers").join(name);
            fs::write(
                &shell,
                format!("#!/bin/sh\ntouch '{}/{name}'\nexit 97\n", hit.display()),
            )
            .unwrap();
            fs::set_permissions(&shell, fs::Permissions::from_mode(0o755)).unwrap();
            let js = project_dir.join("markers").join(format!("{name}.js"));
            fs::write(
                &js,
                format!(
                    "require('fs').writeFileSync('{}/{name}', '');\n",
                    hit.display()
                ),
            )
            .unwrap();
            let line = line
                .replace(&format!("@M:{name}@"), &shell.display().to_string())
                .replace(&format!("@J:{name}@"), &js.display().to_string());
            npmrc.push_str(&line);
            npmrc.push('\n');
        }
        fs::write(project_dir.join(".npmrc"), &npmrc).unwrap();
        let (report, recorded) = through_door(
            harness,
            DoorKind::MissingLock,
            Policy::default(),
            lock_only_run(&node_obj, &project_dir),
        );
        done();
        let report = report.unwrap();
        let text = stderr(&report);
        assert!(report.status.success(), "{text}");
        assert!(recorded.is_empty(), "{recorded:?}");
        assert!(
            fs::read_dir(&hit).unwrap().next().is_none(),
            "a project-named program ran: {:?}",
            fs::read_dir(&hit)
                .unwrap()
                .map(|e| e.unwrap().file_name())
                .collect::<Vec<_>>()
        );
        assert!(!text.contains("/markers/"), "{text}");
        let lock = fs::read_to_string(project_dir.join("package-lock.json")).unwrap();
        assert!(lock.contains("git+file://"), "{lock}");
    }

    /// The pinned pnpm, realized into a `tog x` cache root the test owns:
    /// what `tog add` borrows from its command, for pnpm's door tests. The
    /// realization resolves against the real registry (it needs pnpm's
    /// own tarball), so the harness proxy is switched off around it.
    struct TestHost {
        harness: &'static Harness,
        cache: PathBuf,
    }

    impl EditHost for TestHost {
        fn toolchain(
            &self,
            _dir: &Path,
            _ecosystem: &str,
        ) -> io::Result<crate::kernel::toolchain::Selected> {
            crate::tailors::node::shipped_selection()
        }

        fn cached_tool(
            &self,
            _ecosystem: &str,
            _project: &Path,
            package: &str,
            version: &str,
            door: &mut ResolutionDoor<'_>,
        ) -> io::Result<CachedTool> {
            use crate::tailors::RegistryTool as _;
            let root = self.cache.join(format!("{package}-{version}"));
            let realized = !root.join(".tog/closures/node.json").is_file();
            if realized {
                PROXY_FOR_TEST.with(|slot| slot.set(None));
                let result = crate::tailors::node::registry_tool::NodeTool.realize(
                    door,
                    &root,
                    package,
                    Some(version),
                    &crate::tailors::node::shipped_selection()?,
                    &std::collections::BTreeMap::new(),
                );
                PROXY_FOR_TEST.with(|slot| slot.set(Some(&self.harness.proxy)));
                result?;
            }
            Ok(CachedTool {
                lock: fs::File::open(&root)?,
                root,
                realized,
            })
        }
    }

    const PNPM_VERSION: &str = "9.15.4";

    /// A pnpm project in `dir` pinning [`PNPM_VERSION`].
    fn pnpm_project(dir: &Path, dependencies: &str) -> PathBuf {
        fs::create_dir_all(dir).unwrap();
        fs::write(
            dir.join("package.json"),
            format!(
                "{{\n  \"name\": \"spike\",\n  \"version\": \"1.0.0\",\n  \"packageManager\": \
                 \"pnpm@{PNPM_VERSION}\",\n  \"dependencies\": {{{dependencies}}}\n}}\n"
            ),
        )
        .unwrap();
        dir.canonicalize().unwrap()
    }

    /// Contract 8 for pnpm: the lock the pinned pnpm writes through
    /// interception (with the `--config.` proxy and CA spellings PR 0
    /// found every verb takes) is byte-identical to the one it writes
    /// reaching the same registry directly through a blind forwarder.
    #[test]
    #[ignore = "realizes the store Node and the pinned pnpm over the network"]
    fn pnpm_add_through_interception_lock_matches_direct_run() {
        let _serial = policy::attribution_test_lock();
        let Some(harness) = node_harness(
            "pnpm_add_through_interception_lock_matches_direct_run",
            "pnpm",
        ) else {
            return;
        };
        let node_obj = store_node(harness);
        let temp = TempDir::named("pnpm-lock-identical");
        let intercepted = pnpm_project(&temp.0.join("intercepted"), "");
        let direct = pnpm_project(&temp.0.join("direct"), "");
        let host = TestHost {
            harness,
            cache: temp.0.join("x"),
        };
        let mut attribution = Attribution::open("node").unwrap();
        let mut door = ResolutionDoor::open(
            &harness.store,
            &harness.activity,
            Platform::host().unwrap(),
            DoorKind::Edit,
            &mut attribution,
        )
        .unwrap();
        let pinned = super::super::edit::pinned_pnpm(&mut door, &host, &intercepted, "").unwrap();
        drop(door);
        attribution.discard();
        let args: Vec<String> = [
            "add",
            "--lockfile-only",
            "--reporter",
            "append-only",
            "--",
            "is-odd@3.0.1",
        ]
        .iter()
        .map(|arg| arg.to_string())
        .collect();
        let (report, recorded) = through_door(
            harness,
            DoorKind::Edit,
            Policy::default(),
            NodeRun {
                tool: NodeTool::Pnpm {
                    node_obj: &node_obj,
                    program: &pinned.program,
                },
                lock_root: &intercepted,
                cwd: None,
                args: args.clone(),
                publish: Publish::Project {
                    outputs: vec![
                        PathBuf::from("package.json"),
                        PathBuf::from("pnpm-lock.yaml"),
                    ],
                    receipt: None,
                },
                capture: true,
            },
        );
        done();
        let report = report.unwrap();
        assert!(report.status.success(), "{}", stderr(&report));
        assert!(recorded.is_empty(), "{recorded:?}");
        let entries = ledger_entries(harness, &report);
        assert!(
            entries.iter().any(
                |entry| entry.url == "https://registry.npmjs.org/is-odd" && entry.status == 200
            ),
            "{entries:?}"
        );

        let forwarder = blind_forwarder(harness.upstream.address());
        let ca = temp.0.join("fixture-ca.pem");
        fs::write(&ca, harness.upstream_ca_pem()).unwrap();
        let scratch = temp.0.join("direct-scratch");
        fs::create_dir_all(scratch.join("home")).unwrap();
        let output = std::process::Command::new(node_obj.join("bin/node"))
            .arg(&pinned.program.script)
            .args([
                format!("--config.proxy=http://{forwarder}"),
                format!("--config.https-proxy=http://{forwarder}"),
                "--config.noproxy=".to_string(),
                "--config.registry=https://registry.npmjs.org/".to_string(),
                "--config.strict-ssl=true".to_string(),
                format!("--config.cafile={}", ca.display()),
                "--config.update-notifier=false".to_string(),
                "--config.manage-package-manager-versions=false".to_string(),
                "--config.enable-modules-dir=false".to_string(),
                "--config.node-linker=isolated".to_string(),
                "--config.modules-dir=../direct-scratch/modules".to_string(),
                "--config.virtual-store-dir=../direct-scratch/modules/.pnpm".to_string(),
                format!("--config.store-dir={}", scratch.join("store").display()),
                format!("--config.cache-dir={}", scratch.join("cache").display()),
                "--config.ignore-scripts=true".to_string(),
            ])
            .args(&args)
            .current_dir(&direct)
            .env_clear()
            .env(
                "PATH",
                format!("{}:/usr/bin:/bin", node_obj.join("bin").display()),
            )
            .env("HOME", scratch.join("home"))
            .env("CI", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let through = fs::read_to_string(intercepted.join("pnpm-lock.yaml")).unwrap();
        assert_eq!(
            through,
            fs::read_to_string(direct.join("pnpm-lock.yaml")).unwrap()
        );
        assert!(through.contains("is-odd@3.0.1"), "{through}");
        assert_eq!(
            fs::read_to_string(intercepted.join("package.json")).unwrap(),
            fs::read_to_string(direct.join("package.json")).unwrap()
        );
        assert!(!intercepted.join("node_modules").exists());
    }

    /// `tog attest node` for both tools: npm's lock-only install on an
    /// unchanged lock signs a record covering the manifest and the lock
    /// (and `.npmrc`), and after a dependency is added by hand npm would
    /// rewrite the lock, which is refused; pnpm's frozen lock-only install
    /// attests the lock it wrote and refuses the drifted one.
    #[test]
    #[ignore = "realizes the store Node and the pinned pnpm over the network"]
    fn attest_signs_an_unchanged_node_lock_and_refuses_a_drifted_one() {
        let _serial = policy::attribution_test_lock();
        let Some(harness) = node_harness(
            "attest_signs_an_unchanged_node_lock_and_refuses_a_drifted_one",
            "npm",
        ) else {
            return;
        };
        let node_obj = store_node(harness);
        let selected = crate::tailors::node::shipped_selection().unwrap();
        let temp = TempDir::named("node-attest");
        let host = TestHost {
            harness,
            cache: temp.0.join("x"),
        };
        let attest = |dir: &Path| {
            let held = crate::kernel::fsroot::ProjectRoot::open(dir).unwrap();
            let mut attribution = Attribution::open("node").unwrap();
            let mut door = ResolutionDoor::open(
                &harness.store,
                &harness.activity,
                Platform::host().unwrap(),
                DoorKind::Attest,
                &mut attribution,
            )
            .unwrap();
            let result = super::super::resolve::attest_project(&mut door, &held, &host, &selected);
            drop(door);
            attribution.discard();
            result
        };

        // npm: a lock the door wrote, then a manifest edited by hand.
        let npm_dir = project(&temp.0.join("npm"), "\"is-odd\": \"3.0.1\"");
        fs::write(npm_dir.join(".npmrc"), "fund=true\n").unwrap();
        let (report, _) = through_door(
            harness,
            DoorKind::MissingLock,
            Policy::default(),
            lock_only_run(&node_obj, &npm_dir),
        );
        assert!(report.unwrap().status.success());
        let lock_before = fs::read(npm_dir.join("package-lock.json")).unwrap();
        let (record, _) = attest(&npm_dir).unwrap();
        assert_eq!(record.tool.name, "npm");
        assert!(record.outputs.contains_key("package.json"));
        assert!(record.outputs.contains_key("package-lock.json"));
        assert!(record.inputs.contains_key(".npmrc"));
        assert_eq!(
            fs::read(npm_dir.join("package-lock.json")).unwrap(),
            lock_before
        );
        assert!(!npm_dir.join(".tog/resolution/node.json").exists());
        fs::write(
            npm_dir.join("package.json"),
            "{\n  \"name\": \"spike\",\n  \"version\": \"1.0.0\",\n  \"dependencies\": {\"is-odd\": \"3.0.1\", \"is-number\": \"6.0.0\"}\n}\n",
        )
        .unwrap();
        let error = attest(&npm_dir).unwrap_err().to_string();
        assert!(error.contains("would change package-lock.json"), "{error}");
        assert_eq!(
            fs::read(npm_dir.join("package-lock.json")).unwrap(),
            lock_before
        );

        // pnpm: the same against the pinned pnpm's frozen check. The pnpm
        // fixture rows answer its abbreviated-packument requests.
        let pnpm_rows = stored_rows("pnpm", "attest-pnpm");
        harness.upstream.load_registry(&pnpm_rows.0);
        let pnpm_dir = pnpm_project(&temp.0.join("pnpm"), "\"is-odd\": \"3.0.1\"");
        let error = attest(&pnpm_dir).unwrap_err().to_string();
        assert!(error.contains("no lock to attest"), "{error}");
        let mut attribution = Attribution::open("node").unwrap();
        let mut door = ResolutionDoor::open(
            &harness.store,
            &harness.activity,
            Platform::host().unwrap(),
            DoorKind::MissingLock,
            &mut attribution,
        )
        .unwrap();
        let pinned = super::super::edit::pinned_pnpm(&mut door, &host, &pnpm_dir, "").unwrap();
        drop(door);
        attribution.discard();
        let (report, _) = through_door(
            harness,
            DoorKind::MissingLock,
            Policy::default(),
            NodeRun {
                tool: NodeTool::Pnpm {
                    node_obj: &node_obj,
                    program: &pinned.program,
                },
                lock_root: &pnpm_dir,
                cwd: None,
                args: ["install", "--lockfile-only", "--reporter", "append-only"]
                    .iter()
                    .map(|arg| arg.to_string())
                    .collect(),
                publish: Publish::Project {
                    outputs: vec![
                        PathBuf::from("package.json"),
                        PathBuf::from("pnpm-lock.yaml"),
                    ],
                    receipt: None,
                },
                capture: true,
            },
        );
        let report = report.unwrap();
        assert!(report.status.success(), "{}", stderr(&report));
        let lock_before = fs::read(pnpm_dir.join("pnpm-lock.yaml")).unwrap();
        let (record, _) = attest(&pnpm_dir).unwrap();
        assert_eq!(record.tool.name, "pnpm");
        assert_eq!(record.tool.version, PNPM_VERSION);
        assert!(record.outputs.contains_key("pnpm-lock.yaml"));
        assert_eq!(
            fs::read(pnpm_dir.join("pnpm-lock.yaml")).unwrap(),
            lock_before
        );
        fs::write(
            pnpm_dir.join("package.json"),
            format!(
                "{{\n  \"name\": \"spike\",\n  \"version\": \"1.0.0\",\n  \"packageManager\": \
                 \"pnpm@{PNPM_VERSION}\",\n  \"dependencies\": {{\"is-odd\": \"3.0.1\", \"is-number\": \
                 \"6.0.0\"}}\n}}\n"
            ),
        )
        .unwrap();
        let error = attest(&pnpm_dir).unwrap_err().to_string();
        assert!(error.contains("not what the lock check accepts"), "{error}");
        assert_eq!(
            fs::read(pnpm_dir.join("pnpm-lock.yaml")).unwrap(),
            lock_before
        );
        done();
    }
}

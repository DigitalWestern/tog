//! Running the store uv as a resolver (python tailor): confined through the
//! door, its https traffic intercepted by the proxy session (PyPI through
//! the [`registry`](super::registry) route, git dependencies through the
//! git row, an extra index or a direct URL as `unattested-index`).
//!
//! Every Python resolution goes through here: `tog add`/`remove`/`update`,
//! a missing `requirements.lock.txt`, an sdist's build requirements, `tog
//! x`'s resolution, and `tog attest`'s lock checks. None runs uv directly.
//!
//! How uv is pointed at the session: the proxy variables and
//! `SSL_CERT_FILE` (the session CA, which uv takes as its whole root set)
//! from `door::proxy_env`, and the default index forced on the command
//! line (`--index-url` for `pip compile`, `--default-index` for `add`,
//! `remove`, and `lock`), so a project's `[[tool.uv.index]]` default never
//! replaces PyPI; an extra index it names is still reached, through
//! interception, and recorded as `unattested-index`. The forced row adds
//! `--python <store python>`, `--no-config`, `--no-python-downloads`, and
//! `--keyring-provider disabled`. uv's cache is a directory tog creates for
//! one door operation and removes after it, shared by the probe and the
//! run after it, never by two operations.
//!
//! **The `--no-build` probe.** Whether resolution ran a third-party build
//! backend is established by construction, not guessed from traffic: every
//! uv door first runs with `--no-build`, where no third-party code can
//! run. If that succeeds, its outputs are the result. If uv refuses because
//! a distribution must be built, the names it gives decide: the project's
//! own code (a path under the lock root) has its metadata built first,
//! with its build backend from wheels only, and the probe runs again; a
//! third party's build is `resolution-build`, refused when policy denies
//! it and otherwise recorded, and the run is repeated without `--no-build`.

use super::registry;
use crate::kernel::activity::StoreActivity;
use crate::kernel::platform::Platform;
use crate::kernel::policy::{self, Policy};
use crate::kernel::resolve::door::{self, ConfinedSpec, Publish, Wire, Wiring};
use crate::kernel::resolve::record::{self, RecordSlot, RecordSpec};
use crate::kernel::resolve::session::{Fact, Intercept};
use crate::kernel::resolve::snapshot::PathGlob;
use crate::kernel::resolve::{DelegateReport, DelegateSpec, ResolutionDoor};
use crate::kernel::store::Store;
use crate::kernel::toolchain::Selected;
use std::ffi::OsString;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// Why uv runs isolated, for the missing-capability message.
pub(crate) const WHY_UV: &str = "runs the build backends of source distributions it resolves, \
                                 and fetches packages from the network";

/// The header line uv writes into a compiled lock in place of its own
/// command line, which names the store interpreter's path (a different
/// path on every machine) and the probe's `--no-build`. With it, the same
/// resolution writes the same bytes everywhere, which `tog attest` checks.
pub(crate) const COMPILE_COMMAND: &str = "tog";

/// The store uv and the interpreter it resolves and builds with.
pub(crate) struct Uv {
    /// The uv object (the binary is `uv` in it).
    pub obj: PathBuf,
    /// The CPython object.
    pub runtime: PathBuf,
    pub version: String,
}

impl Uv {
    /// The uv and CPython `selected` names, realized.
    pub(crate) fn realize(
        store: &Store,
        activity: &StoreActivity,
        platform: Platform,
        selected: &Selected,
    ) -> io::Result<Uv> {
        let obj = super::realize_uv(store, activity, platform, selected)?;
        let runtime = super::realize_runtime(store, activity, platform, selected)?;
        let version = selected.version("uv")?.to_string();
        Ok(Uv {
            obj,
            runtime,
            version,
        })
    }

    /// [`Uv::realize`] on `door`'s store.
    pub(crate) fn for_door(door: &ResolutionDoor<'_>, selected: &Selected) -> io::Result<Uv> {
        Uv::realize(door.store(), door.lease(), door.platform(), selected)
    }

    pub(crate) fn binary(&self) -> PathBuf {
        self.obj.join("uv")
    }

    /// The interpreter every uv run is given as `--python`.
    pub(crate) fn python(&self) -> PathBuf {
        self.runtime.join("bin/python3")
    }

    /// The uv a resolution record names.
    pub(crate) fn tool(&self) -> record::Tool {
        record::Tool {
            name: "uv".to_string(),
            version: self.version.clone(),
        }
    }
}

/// How a run's subcommand takes the forced default index.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Index {
    /// `uv pip compile`: `--index-url`.
    PipCompile,
    /// `uv add`, `remove`, `lock`: `--default-index`.
    Project,
}

impl Index {
    fn flag(self) -> &'static str {
        match self {
            Index::PipCompile => "--index-url",
            Index::Project => "--default-index",
        }
    }
}

/// Whether a run may build.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Builds {
    /// The probe first, then a run that may build when the probe needed it
    /// and policy allows `resolution-build`.
    Probe,
    /// `--no-build` only: a build need is an error (an sdist's build
    /// requirements, which are metadata inputs, not permission to run
    /// backends).
    Never,
}

/// Where a run's accepted outputs go.
pub(crate) enum UvTarget {
    /// The lock root is a project: the outputs are published through the
    /// transaction, with the record `record` describes (none: the outputs
    /// alone, which a sync then records as `unrecorded-resolution`).
    Project {
        record: Option<RecordSpec>,
        slot: RecordSlot,
    },
    /// The lock root is tog's own (a `tog x` cache root, a scratch
    /// directory): accepted outputs are written back into it.
    Detached,
}

/// One confined uv operation: the probe and whatever runs after it.
pub(crate) struct UvRun<'a> {
    pub uv: &'a Uv,
    /// Where the lock lives: the project, or the uv workspace root.
    pub lock_root: &'a Path,
    /// Where uv runs, relative to the lock root (a workspace member);
    /// `None` is the lock root.
    pub cwd: Option<PathBuf>,
    /// The subcommand and its arguments. The door adds the index, the
    /// build flag, and the forced row; a `--` here keeps its operands last.
    pub args: Vec<OsString>,
    pub index: Index,
    pub outputs: Vec<PathBuf>,
    pub target: UvTarget,
    pub builds: Builds,
    /// Capture uv's output into the report instead of letting the user
    /// watch it. The probe is always captured; when it is the last run, an
    /// uncaptured operation shows what it printed.
    pub capture: bool,
    /// `None` is the process policy (tests set one).
    pub policy: Option<Policy>,
}

/// What a probe failure says must be built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BuildNeed {
    pub name: String,
    /// The distribution's location when uv names one (`<name> @ <url>`).
    pub url: Option<String>,
}

/// The distributions a `--no-build` refusal names, from uv's two forms
/// (PR 0, uv 0.12.7): "Wheels are required for `<name>` because building
/// from source is disabled", and "Failed to build `<name> @ <url>`" with
/// "Building source distributions for `<name>` is disabled". Empty when
/// the failure was something else.
pub(crate) fn build_needs(stderr: &str) -> Vec<BuildNeed> {
    if !stderr.contains("is disabled") {
        return Vec::new();
    }
    // uv wraps a long message across lines behind its box drawing (`×`,
    // `│`, `╰─▶`), at a space: one line again, so a name and its url are
    // read whole.
    let text = stderr
        .lines()
        .map(|line| {
            line.trim_start_matches(|ch: char| {
                ch.is_whitespace() || matches!(ch, '×' | '│' | '╰' | '├' | '─' | '▶')
            })
            .trim_end()
        })
        .collect::<Vec<_>>()
        .join(" ");
    let mut needs: Vec<BuildNeed> = Vec::new();
    let mut push = |name: &str, url: Option<String>| {
        let name = name.trim().to_string();
        if name.is_empty() {
            return;
        }
        match needs.iter_mut().find(|need| need.name == name) {
            Some(need) => {
                if need.url.is_none() {
                    need.url = url;
                }
            }
            None => needs.push(BuildNeed { name, url }),
        }
    };
    // Every backquoted text after `marker`, in order.
    let quoted = |marker: &str| -> Vec<String> {
        let mut found = Vec::new();
        let mut rest = text.as_str();
        while let Some(at) = rest.find(marker) {
            rest = &rest[at + marker.len()..];
            let Some(end) = rest.find('`') else {
                break;
            };
            found.push(rest[..end].to_string());
            rest = &rest[end..];
        }
        found
    };
    for built in quoted("Failed to build `") {
        match built.split_once(" @ ") {
            Some((name, url)) => push(name, Some(url.trim().to_string())),
            None => push(&built, None),
        }
    }
    for marker in [
        "Wheels are required for `",
        "Building source distributions for `",
    ] {
        for name in quoted(marker) {
            push(&name, None);
        }
    }
    needs
}

/// The directory of a build need under `lock_root`: the project's own code
/// (a workspace member, the root project, a path dependency inside the
/// project), whose build is not a third party's.
fn own_directory(need: &BuildNeed, lock_root: &Path) -> Option<PathBuf> {
    let url = url::Url::parse(need.url.as_deref()?).ok()?;
    if url.scheme() != "file" {
        return None;
    }
    let path = url.to_file_path().ok()?;
    let real = std::fs::canonicalize(&path).ok()?;
    let root = std::fs::canonicalize(lock_root).ok()?;
    real.starts_with(&root).then_some(real)
}

/// The project names a `pyproject.toml`'s `build-system.requires` lists,
/// or setuptools when there is none (PEP 517's default backend).
fn build_requirement_names(dir: &Path) -> Vec<String> {
    let text = std::fs::read_to_string(dir.join("pyproject.toml")).unwrap_or_default();
    let names: Vec<String> = text
        .parse::<toml::Table>()
        .ok()
        .and_then(|table| {
            table
                .get("build-system")?
                .get("requires")?
                .as_array()
                .cloned()
        })
        .unwrap_or_default()
        .iter()
        .filter_map(|value| value.as_str())
        .filter_map(super::edit::requirement_name)
        .collect();
    if names.is_empty() {
        vec!["setuptools".to_string()]
    } else {
        names
    }
}

/// uv's cache for one door operation: a store stage, bound read-write into
/// each of the operation's runs and removed when the operation ends.
struct UvCache {
    dir: PathBuf,
    /// The pre-step inputs written so far.
    count: std::cell::Cell<usize>,
}

impl UvCache {
    fn create(store: &Store, activity: &StoreActivity) -> io::Result<UvCache> {
        Ok(UvCache {
            dir: store.stage_with_activity(activity)?,
            count: std::cell::Cell::new(0),
        })
    }
}

impl Drop for UvCache {
    fn drop(&mut self) {
        let _ = crate::kernel::store::remove_tree(&self.dir);
    }
}

/// Paths a uv run may leave in the project's tree that are never results:
/// metadata and build directories a backend writes beside its own source
/// (setuptools' `*.egg-info`, `build/`), and bytecode caches. Discarded.
const SCRATCH: [&str; 3] = ["**/*.egg-info", "**/build", "**/__pycache__"];

/// The project's own environment (a symlink into the store) is never a
/// resolution input.
const EXCLUDE: [&str; 1] = ["**/.venv"];

/// One run's flags: `args` with the index, the build flag, and `forced`
/// placed before a `--`.
fn with_flags(args: &[OsString], flags: &[OsString]) -> Vec<OsString> {
    let split = args
        .iter()
        .position(|arg| arg == "--")
        .unwrap_or(args.len());
    let mut all = args[..split].to_vec();
    all.extend(flags.iter().cloned());
    all.extend(args[split..].iter().cloned());
    all
}

/// The arguments of one attempt, before the forced row.
fn attempt_args(run: &UvRun<'_>, no_build: bool) -> Vec<OsString> {
    let mut flags: Vec<OsString> = vec![run.index.flag().into(), registry::INDEX_URL.into()];
    if no_build {
        flags.push("--no-build".into());
    }
    with_flags(&run.args, &flags)
}

/// A record spec for an attempt that ran `args`.
fn record_for(spec: &RecordSpec, args: &[OsString]) -> RecordSpec {
    let mut command = vec![spec.tool.name.clone()];
    command.extend(args.iter().map(|arg| arg.to_string_lossy().into_owned()));
    RecordSpec {
        tool: spec.tool.clone(),
        command,
        files: spec.files.clone(),
        key: spec.key.clone(),
        require_unchanged: spec.require_unchanged,
        publish_receipt: spec.publish_receipt,
    }
}

/// One confined uv invocation.
struct Attempt<'r> {
    lock_root: &'r Path,
    cwd: Option<PathBuf>,
    args: Vec<OsString>,
    publish: Publish<'r>,
    capture: bool,
    facts: Vec<Fact>,
}

/// The `ConfinedSpec` and invocation of one attempt, through the process
/// proxy with TLS interception on the PyPI route.
fn confined<'r>(
    uv: &'r Uv,
    python: &'r Path,
    cache: &Path,
    attempt: Attempt<'r>,
) -> io::Result<(DelegateSpec, ConfinedSpec<'r>)> {
    let mut spec = DelegateSpec::new(uv.binary());
    spec.args(&attempt.args)
        .lock_root(attempt.lock_root)
        // The host's own tools: git for a git dependency, and the compilers
        // an sdist's backend may call when a build is allowed.
        .env("PATH", "/usr/bin:/bin")
        .env("UV_PYTHON_DOWNLOADS", "never")
        .env("UV_NO_PROGRESS", "1");
    if attempt.capture {
        spec.capture();
    }
    let mut confined = ConfinedSpec::new("python", "uv", WHY_UV);
    confined.forced.python = Some(python);
    confined.store_reads = vec![uv.obj.clone(), uv.runtime.clone()];
    confined.cache_roots = vec![cache.to_path_buf()];
    confined.exclude = EXCLUDE
        .iter()
        .map(|glob| PathGlob::new(glob))
        .collect::<io::Result<_>>()?;
    confined.scratch_outputs = SCRATCH
        .iter()
        .map(|glob| PathGlob::new(glob))
        .collect::<io::Result<_>>()?;
    confined.routes = vec![registry::route()?];
    confined.intercept = Intercept::Tls;
    confined.cwd = attempt.cwd;
    confined.facts = attempt.facts;
    let cache = cache.to_path_buf();
    confined.wire = Some(Box::new(move |wire: &Wire<'_>| wiring(wire, &cache)));
    confined.publish(attempt.publish);
    Ok((spec, confined))
}

/// The forced row before any `--`, the proxy environment, and the cache.
fn wiring(wire: &Wire<'_>, cache: &Path) -> io::Result<Wiring> {
    let ca_file = wire.ca_file.ok_or_else(|| {
        io::Error::other("uv resolves only through TLS interception, which this run lacks")
    })?;
    let mut env = door::proxy_env(wire.address, ca_file);
    env.push(("UV_CACHE_DIR".into(), cache.as_os_str().to_os_string()));
    Ok(Wiring {
        args: with_flags(wire.args, wire.forced_args),
        env,
        ..Wiring::default()
    })
}

/// Run `run` through `door`: the probe and what follows it. A run that
/// exits nonzero for any reason but a build need is a report, which the
/// caller words. A Detached run's ledger ids come back in the report.
pub(crate) fn run_uv(door: &mut ResolutionDoor<'_>, run: UvRun<'_>) -> io::Result<DelegateReport> {
    let cache = UvCache::create(door.store(), door.lease())?;
    let python = run.uv.python();
    match run.builds {
        Builds::Never => attempt(door, &run, &python, &cache, true, run.capture, Vec::new()),
        Builds::Probe => probe_then_run(door, &run, &python, &cache),
    }
}

fn probe_then_run(
    door: &mut ResolutionDoor<'_>,
    run: &UvRun<'_>,
    python: &Path,
    cache: &UvCache,
) -> io::Result<DelegateReport> {
    let mut built_own: Vec<PathBuf> = Vec::new();
    let mut third_party: Vec<String> = Vec::new();
    loop {
        let probe = attempt(door, run, python, cache, true, true, Vec::new())?;
        if probe.status.success() {
            if !run.capture {
                let _ = io::stderr().write_all(&probe.stderr);
                let _ = io::stdout().write_all(&probe.stdout);
            }
            return Ok(probe);
        }
        let stderr = String::from_utf8_lossy(&probe.stderr).into_owned();
        let needs = build_needs(&stderr);
        if needs.is_empty() {
            return Ok(probe);
        }
        let mut progressed = false;
        for need in &needs {
            match own_directory(need, run.lock_root) {
                Some(dir) if !built_own.contains(&dir) => {
                    // The project's own code: its metadata, built with its
                    // backend from wheels only. A backend that is itself
                    // sdist-only is a third party's build.
                    match own_metadata(door, run, python, cache, &dir)? {
                        None => {}
                        Some(requires) => third_party.extend(requires),
                    }
                    built_own.push(dir);
                    progressed = true;
                }
                Some(_) => {}
                None => third_party.push(need.name.clone()),
            }
        }
        if progressed && third_party.is_empty() {
            continue;
        }
        if third_party.is_empty() {
            // Only the project's own builds, already prepared: the probe
            // still needs them, so uv's own words are the answer.
            return Ok(probe);
        }
        break;
    }
    third_party.sort();
    third_party.dedup();
    let subject = third_party.join(", ");
    let detail = "resolving needed to build these source distributions, or the project's own \
                  build backend could not come from wheels alone (their build code runs, \
                  confined); uv's --no-build probe could not finish without them"
        .to_string();
    let policy = run.policy.clone().unwrap_or_else(policy::effective);
    if policy::denied(&policy, policy::RESOLUTION_BUILD) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            policy::refusal(&policy, policy::RESOLUTION_BUILD, &subject, &detail),
        ));
    }
    let facts = vec![Fact {
        kind: policy::RESOLUTION_BUILD,
        subject,
        detail,
    }];
    attempt(door, run, python, cache, false, run.capture, facts)
}

/// Build the metadata of the project's own distribution at `dir` into the
/// operation's cache, its build backend from wheels only, so the probe that
/// follows reuses it. `Some(requirements)` when the backend could not come
/// from wheels: those requirements are a third party's build.
fn own_metadata(
    door: &mut ResolutionDoor<'_>,
    run: &UvRun<'_>,
    python: &Path,
    cache: &UvCache,
    dir: &Path,
) -> io::Result<Option<Vec<String>>> {
    // `uv pip compile` takes its requirements from a file: one naming the
    // directory editable, written in the operation's cache (bound into the
    // run read-write), never in the project. The snapshot is at the
    // project's own path, so the path names it there.
    let requires = build_requirement_names(dir);
    let input = cache.dir.join(format!("own-{}.in", cache.count.get()));
    cache.count.set(cache.count.get() + 1);
    std::fs::write(&input, format!("-e {}\n", dir.display()))?;
    let args: Vec<OsString> = vec![
        "pip".into(),
        "compile".into(),
        "--quiet".into(),
        "--no-deps".into(),
        "--only-binary".into(),
        requires.join(",").into(),
        Index::PipCompile.flag().into(),
        registry::INDEX_URL.into(),
        input.into_os_string(),
    ];
    let (spec, confined) = confined(
        run.uv,
        python,
        &cache.dir,
        Attempt {
            lock_root: run.lock_root,
            cwd: None,
            args,
            publish: Publish::Detached {
                outputs: Vec::new(),
            },
            capture: true,
            facts: Vec::new(),
        },
    )?;
    spec.trace();
    let report = door.run_confined(spec, confined)?;
    if report.status.success() {
        return Ok(None);
    }
    Ok(Some(requires))
}

/// One attempt of `run`, with or without `--no-build`.
fn attempt(
    door: &mut ResolutionDoor<'_>,
    run: &UvRun<'_>,
    python: &Path,
    cache: &UvCache,
    no_build: bool,
    capture: bool,
    facts: Vec<Fact>,
) -> io::Result<DelegateReport> {
    let args = attempt_args(run, no_build);
    let publish = match &run.target {
        UvTarget::Project { record, slot } => Publish::Project {
            outputs: run.outputs.clone(),
            receipt: record
                .as_ref()
                .map(|spec| record::producer(record_for(spec, &args), slot.clone())),
        },
        UvTarget::Detached => Publish::Detached {
            outputs: run.outputs.clone(),
        },
    };
    let (spec, mut confined) = confined(
        run.uv,
        python,
        &cache.dir,
        Attempt {
            lock_root: run.lock_root,
            cwd: run.cwd.clone(),
            args: args.clone(),
            publish,
            capture,
            facts,
        },
    )?;
    confined.policy = run.policy.clone();
    spec.trace();
    door.run_confined(spec, confined).map_err(|error| {
        let shown: Vec<String> = args
            .iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        io::Error::new(
            error.kind(),
            format!("store uv {}: {error}", shown.join(" ")),
        )
    })
}

/// `run_uv` that fails on a nonzero exit, as `what` failed, with the tail
/// of what uv said when it was captured.
pub(crate) fn run_uv_checked(
    door: &mut ResolutionDoor<'_>,
    run: UvRun<'_>,
    what: &str,
) -> io::Result<DelegateReport> {
    let report = run_uv(door, run)?;
    if !report.status.success() {
        let words = crate::kernel::resolve::confine::scrub_signing_key(&String::from_utf8_lossy(
            &report.stderr,
        ));
        return Err(super::uv_failure(what, report.status, words.as_bytes()));
    }
    Ok(report)
}

/// The ledger of a Detached run, rooted under `root` (a `tog x` cache
/// root), the way a planner door's ledger is rooted under its project, so
/// GC keeps it with the root.
pub(crate) fn root_ledger(
    door: &ResolutionDoor<'_>,
    root: &Path,
    report: &DelegateReport,
) -> io::Result<()> {
    if let Some(objects) = &report.ledger {
        let held = crate::kernel::fsroot::ProjectRoot::open(root)?;
        crate::kernel::resolve::ledger::root(door.store(), door.lease(), &held, objects)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// PR 0's two forms of the `--no-build` refusal, and an ordinary
    /// failure that names nothing.
    #[test]
    fn the_probe_reads_both_refusal_forms() {
        let wheels = "  × No solution found when resolving dependencies:\n  ╰─▶ Because docopt==0.6.2 has no usable wheels and you require docopt, we can conclude that your requirements are unsatisfiable.\n\n      hint: Wheels are required for `docopt` because building from source is disabled for all packages (i.e., with `--no-build`)\n";
        assert_eq!(
            build_needs(wheels),
            vec![BuildNeed {
                name: "docopt".into(),
                url: None
            }]
        );
        let member = "error: Failed to build `dyn @ file:///work/proj`\n  ╰─▶ Building source distributions for `dyn` is disabled\n";
        assert_eq!(
            build_needs(member),
            vec![BuildNeed {
                name: "dyn".into(),
                url: Some("file:///work/proj".into())
            }]
        );
        // uv 0.12.7 wraps a long url onto its own line.
        let wrapped = "  × Failed to build `spike @\n  │ file:///work/project`\n  ╰─▶ Building source distributions for `spike` is disabled\n";
        assert_eq!(
            build_needs(wrapped),
            vec![BuildNeed {
                name: "spike".into(),
                url: Some("file:///work/project".into())
            }]
        );
        let ordinary = "error: Request failed after 3 retries\n  Caused by: Failed to fetch: `https://pypi.org/simple/nope/`\n";
        assert!(build_needs(ordinary).is_empty());
        // A name given twice is one need, keeping the url either form gave.
        let both = format!("{member}hint: Wheels are required for `dyn` because building from source is disabled\n");
        assert_eq!(build_needs(&both).len(), 1);
    }

    #[test]
    fn own_code_is_a_file_url_under_the_lock_root() {
        let temp = crate::kernel::testutil::TempDir::named("uv-own");
        let root = temp.0.join("proj");
        std::fs::create_dir_all(root.join("member")).unwrap();
        std::fs::create_dir_all(temp.0.join("elsewhere")).unwrap();
        let need = |url: String| BuildNeed {
            name: "x".into(),
            url: Some(url),
        };
        let member = url::Url::from_file_path(root.join("member")).unwrap();
        assert_eq!(
            own_directory(&need(member.to_string()), &root),
            Some(root.join("member").canonicalize().unwrap())
        );
        let outside = url::Url::from_file_path(temp.0.join("elsewhere")).unwrap();
        assert_eq!(own_directory(&need(outside.to_string()), &root), None);
        assert_eq!(
            own_directory(&need("https://example.test/x.tar.gz".into()), &root),
            None
        );
        assert_eq!(
            own_directory(
                &BuildNeed {
                    name: "x".into(),
                    url: None
                },
                &root
            ),
            None
        );
    }

    #[test]
    fn build_requirements_default_to_setuptools() {
        let temp = crate::kernel::testutil::TempDir::named("uv-build-reqs");
        assert_eq!(build_requirement_names(&temp.0), ["setuptools"]);
        std::fs::write(
            temp.0.join("pyproject.toml"),
            "[build-system]\nrequires = [\"hatchling>=1\", \"hatch-vcs\"]\nbuild-backend = \"hatchling.build\"\n",
        )
        .unwrap();
        assert_eq!(build_requirement_names(&temp.0), ["hatchling", "hatch-vcs"]);
    }

    /// The index and the build flag go before `--`, so the operands stay
    /// last; the probe adds `--no-build`, the run after it does not.
    #[test]
    fn flags_go_before_the_operands() {
        let args: Vec<OsString> = ["add", "--no-sync", "--", "six"]
            .iter()
            .map(OsString::from)
            .collect();
        let uv = Uv {
            obj: PathBuf::from("/s/uv"),
            runtime: PathBuf::from("/s/py"),
            version: "0.12.7".into(),
        };
        let run = UvRun {
            uv: &uv,
            lock_root: Path::new("/p"),
            cwd: None,
            args,
            index: Index::Project,
            outputs: Vec::new(),
            target: UvTarget::Detached,
            builds: Builds::Probe,
            capture: true,
            policy: None,
        };
        let shown = |args: Vec<OsString>| -> Vec<String> {
            args.iter()
                .map(|arg| arg.to_string_lossy().into_owned())
                .collect()
        };
        assert_eq!(
            shown(attempt_args(&run, true)),
            [
                "add",
                "--no-sync",
                "--default-index",
                "https://pypi.org/simple",
                "--no-build",
                "--",
                "six"
            ]
        );
        assert_eq!(
            shown(attempt_args(&run, false)),
            [
                "add",
                "--no-sync",
                "--default-index",
                "https://pypi.org/simple",
                "--",
                "six"
            ]
        );
        assert_eq!(uv.python(), PathBuf::from("/s/py/bin/python3"));
        assert_eq!(uv.binary(), PathBuf::from("/s/uv/uv"));
    }

    use crate::kernel::fsroot::ProjectRoot;
    use crate::kernel::policy::{Attribution, Exception};
    use crate::kernel::resolve::door::{PROXY_FOR_TEST, RELAY_FOR_TEST, SKIP_SCAN_FOR_TEST};
    use crate::kernel::resolve::ledger::{self, Entry};
    use crate::kernel::resolve::testing::{relay, stored_rows, Harness, Reach, TEST_ORIGIN_PUBLIC};
    use crate::kernel::resolve::DoorKind;
    use crate::kernel::testutil::TempDir;
    use std::fs;

    const PYPI_HOSTS: &[&str] = &[
        registry::INDEX_HOST,
        registry::FILES_HOST,
        "github.com",
        "api.github.com",
        "raw.githubusercontent.com",
    ];

    /// A harness whose upstream answers from the recorded PyPI and GitHub
    /// rows, and whose proxy every door in this thread uses while it lives.
    fn uv_harness(label: &str) -> Option<&'static Harness> {
        let relay = relay(label)?;
        RELAY_FOR_TEST.with(|slot| *slot.borrow_mut() = Some(relay));
        SKIP_SCAN_FOR_TEST.with(|skip| skip.set(true));
        let mut reach = Reach::public(|_, _| vec![TEST_ORIGIN_PUBLIC.parse().unwrap()]);
        reach.request_timeout = std::time::Duration::from_secs(20);
        let rows = stored_rows("python", label);
        let harness: &'static Harness = Box::leak(Box::new(Harness::serving(
            label,
            reach,
            PYPI_HOSTS,
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

    /// The store uv and CPython, realized in the harness's store over the
    /// network (not through the door).
    fn store_uv(harness: &Harness) -> Uv {
        let selected =
            super::super::shipped_selection(super::super::pyselect::DEFAULT_VERSION).unwrap();
        Uv::realize(
            &harness.store,
            &harness.activity,
            Platform::host().unwrap(),
            &selected,
        )
        .unwrap()
    }

    /// `run` through a door of `kind`, and what the door recorded.
    fn through_door(
        harness: &Harness,
        kind: DoorKind,
        run: UvRun<'_>,
    ) -> (io::Result<DelegateReport>, Vec<Exception>) {
        let mut attribution = Attribution::open("python").unwrap();
        let mut door = ResolutionDoor::open(
            &harness.store,
            &harness.activity,
            Platform::host().unwrap(),
            kind,
            &mut attribution,
        )
        .unwrap();
        let report = run_uv(&mut door, run);
        drop(door);
        let recorded = attribution.recorded();
        attribution.discard();
        (report, recorded)
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

    /// A missing requirements lock, compiled by the store uv through
    /// interception: every request is a PyPI read the route claims, the
    /// probe needs no build, and the door publishes the lock (headed by
    /// tog's compile command, so it is the same bytes everywhere) with its
    /// resolution record.
    #[test]
    #[ignore = "realizes the store uv and CPython over the network"]
    fn uv_compile_through_interception_publishes_the_lock_with_its_record() {
        let _serial = policy::attribution_test_lock();
        let label = "uv_compile_through_interception_publishes_the_lock_with_its_record";
        let Some(harness) = uv_harness(label) else {
            return;
        };
        let uv = store_uv(harness);
        let temp = TempDir::named("uv-missing-lock");
        let dir = temp.0.join("project");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("requirements.in"),
            "iniconfig==2.3.0\nsix==1.16.0\n",
        )
        .unwrap();
        let dir = dir.canonicalize().unwrap();
        let held = ProjectRoot::open(&dir).unwrap();
        let args =
            super::super::resolve::compile_args("requirements.in", "requirements.lock.txt", "3.12");
        let shown: Vec<String> = args
            .iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        let refs: Vec<&str> = shown.iter().map(String::as_str).collect();
        let spec =
            crate::tailors::record_spec(&super::super::tailor::Python, &held, uv.tool(), &refs)
                .unwrap();
        let (report, recorded) = through_door(
            harness,
            DoorKind::MissingLock,
            UvRun {
                uv: &uv,
                lock_root: &dir,
                cwd: None,
                args,
                index: Index::PipCompile,
                outputs: super::super::resolve::resolution_outputs(&held).unwrap(),
                target: UvTarget::Project {
                    record: Some(spec),
                    slot: Default::default(),
                },
                builds: Builds::Probe,
                capture: true,
                policy: Some(Policy::default()),
            },
        );
        let report = report.unwrap();
        assert!(report.status.success(), "{}", stderr(&report));
        assert!(recorded.is_empty(), "{recorded:?}");
        let lock = fs::read_to_string(dir.join("requirements.lock.txt")).unwrap();
        assert!(super::super::resolve::compiled_by_tog(&lock), "{lock}");
        assert!(lock.contains("six==1.16.0"), "{lock}");
        assert!(lock.contains("--hash=sha256:"), "{lock}");
        assert!(dir.join(".tog/resolution/python.json").is_file());
        let entries = ledger_entries(harness, &report);
        assert!(!entries.is_empty());
        for entry in &entries {
            assert!(
                entry.url.starts_with("https://pypi.org/simple/")
                    || entry
                        .url
                        .starts_with("https://files.pythonhosted.org/packages/"),
                "{entries:?}"
            );
        }
        done();
    }

    /// A requirement with no wheel at all (docopt 0.6.2, sdist only): the
    /// probe stops at it, and with `resolution-build` denied the door fails
    /// naming it and nothing lands. (The allowed rerun would fetch the
    /// sdist and its backend, which the recorded rows do not hold.)
    #[test]
    #[ignore = "realizes the store uv and CPython over the network"]
    fn a_third_party_build_is_refused_when_denied() {
        let _serial = policy::attribution_test_lock();
        let label = "a_third_party_build_is_refused_when_denied";
        let Some(harness) = uv_harness(label) else {
            return;
        };
        let uv = store_uv(harness);
        let temp = TempDir::named("uv-build-need");
        let dir = temp.0.join("project");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("requirements.in"), "docopt==0.6.2\n").unwrap();
        let dir = dir.canonicalize().unwrap();
        let held = ProjectRoot::open(&dir).unwrap();
        let denied = Policy {
            deny: [policy::RESOLUTION_BUILD.to_string()].into(),
            ..Policy::default()
        };
        let (report, recorded) = through_door(
            harness,
            DoorKind::MissingLock,
            UvRun {
                uv: &uv,
                lock_root: &dir,
                cwd: None,
                args: super::super::resolve::compile_args(
                    "requirements.in",
                    "requirements.lock.txt",
                    "3.12",
                ),
                index: Index::PipCompile,
                outputs: super::super::resolve::resolution_outputs(&held).unwrap(),
                target: UvTarget::Project {
                    record: None,
                    slot: Default::default(),
                },
                builds: Builds::Probe,
                capture: true,
                policy: Some(denied),
            },
        );
        done();
        let error = report.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied, "{error}");
        let error = error.to_string();
        assert!(error.contains("resolution-build"), "{error}");
        assert!(error.contains("docopt"), "{error}");
        assert!(recorded.is_empty(), "{recorded:?}");
        assert!(!dir.join("requirements.lock.txt").exists());
    }

    /// The project's own build is not a third party's: a project whose
    /// version is dynamic (hatchling reads it from the source) fails the
    /// probe on itself, and the door builds its metadata in a pre-step with
    /// the backend from wheels only. Here that pre-step cannot finish (the
    /// editable build also asks for `editables`, which the recorded rows do
    /// not hold), so the door treats the backend's requirements as the
    /// third-party build: denied, the refusal names `hatchling`, never the
    /// project itself.
    #[test]
    #[ignore = "realizes the store uv and CPython over the network"]
    fn the_projects_own_build_goes_through_the_metadata_pre_step() {
        let _serial = policy::attribution_test_lock();
        let label = "the_projects_own_build_goes_through_the_metadata_pre_step";
        let Some(harness) = uv_harness(label) else {
            return;
        };
        let uv = store_uv(harness);
        let temp = TempDir::named("uv-own-build");
        let dir = temp.0.join("project");
        fs::create_dir_all(dir.join("spike")).unwrap();
        fs::write(
            dir.join("pyproject.toml"),
            "[project]\nname = \"spike\"\ndynamic = [\"version\"]\nrequires-python = \">=3.12\"\ndependencies = []\n\n[build-system]\nrequires = [\"hatchling\"]\nbuild-backend = \"hatchling.build\"\n\n[tool.hatch.version]\npath = \"spike/__init__.py\"\n",
        )
        .unwrap();
        fs::write(dir.join("spike/__init__.py"), "__version__ = \"0.3.0\"\n").unwrap();
        let dir = dir.canonicalize().unwrap();
        let held = ProjectRoot::open(&dir).unwrap();
        let denied = Policy {
            deny: [policy::RESOLUTION_BUILD.to_string()].into(),
            ..Policy::default()
        };
        let (report, recorded) = through_door(
            harness,
            DoorKind::Edit,
            UvRun {
                uv: &uv,
                lock_root: &dir,
                cwd: None,
                args: vec!["lock".into()],
                index: Index::Project,
                outputs: super::super::resolve::resolution_outputs(&held).unwrap(),
                target: UvTarget::Project {
                    record: None,
                    slot: Default::default(),
                },
                builds: Builds::Probe,
                capture: true,
                policy: Some(denied),
            },
        );
        done();
        let error = report.unwrap_err().to_string();
        assert!(error.contains("resolution-build: hatchling:"), "{error}");
        assert!(!error.contains("spike"), "{error}");
        assert!(recorded.is_empty(), "{recorded:?}");
        assert!(!dir.join("uv.lock").exists());
        // The pre-step's input went into the operation's cache, which is
        // gone: nothing was written into the project.
        let mut names: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        names.sort();
        assert_eq!(names, ["pyproject.toml", "spike"]);
    }
}

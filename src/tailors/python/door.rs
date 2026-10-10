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
//! one attempt and removes after it. An allowed retry has a fresh cache,
//! so its ledger covers the metadata and artifacts it actually consumed.
//!
//! **The `--no-build` probe.** Whether resolution ran a third-party build
//! backend is established by construction, not guessed from traffic: every
//! uv door first runs with `--no-build`, where no third-party code can
//! run. If that succeeds, its outputs are the result. If uv refuses because
//! a distribution needs a source build or metadata preparation, every build
//! (including the project's own backend) requires `resolution-build`
//! permission before it runs. Allowed builds are recorded and the run is
//! repeated without `--no-build`.

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
use crate::kernel::ui;
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

/// uv's cache for one attempt: a private store stage, bound read-write
/// into that attempt and removed when it ends.
struct UvCache {
    dir: PathBuf,
}

impl UvCache {
    fn create(store: &Store, activity: &StoreActivity) -> io::Result<UvCache> {
        Ok(UvCache {
            dir: store.stage_with_activity(activity)?,
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
    // Metadata prepared before uv still contributed to this resolution.
    // Include its provenance on both the probe and a fresh-cache retry.
    let mut prepared: Vec<Fact> = door
        .attribution()
        .recorded()
        .into_iter()
        .filter(|fact| fact.kind == policy::RESOLUTION_BUILD && fact.subject == "setup.py")
        .map(|fact| Fact {
            kind: policy::RESOLUTION_BUILD,
            subject: fact.subject,
            detail: fact.detail,
        })
        .collect();
    let probe = attempt(door, run, python, cache, true, true, prepared.clone())?;
    if probe.status.success() {
        if !run.capture {
            let _ = ui::narration().write_all(&probe.stderr);
            let _ = io::stdout().write_all(&probe.stdout);
        }
        return Ok(probe);
    }
    let needs = build_needs(&String::from_utf8_lossy(&probe.stderr));
    if needs.is_empty() {
        return Ok(probe);
    }
    let mut names: Vec<_> = needs.into_iter().map(|need| need.name).collect();
    names.sort();
    names.dedup();
    let subject = names.join(", ");
    let detail = "resolution needs source builds or metadata preparation, including the \
                  project's own backend and its dynamic build requirements; uv's --no-build \
                  probe could not finish without executing build code (confined)"
        .to_string();
    let policy = run.policy.clone().unwrap_or_else(policy::effective);
    if policy::denied(&policy, policy::RESOLUTION_BUILD) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            policy::refusal(&policy, policy::RESOLUTION_BUILD, &subject, &detail),
        ));
    }
    prepared.push(Fact {
        kind: policy::RESOLUTION_BUILD,
        subject,
        detail,
    });
    // Failed probes may have warmed uv's metadata and artifact caches.
    // Re-resolve with an empty cache so every contributing request and
    // exception belongs to the session that signs the accepted outputs.
    let retry_cache = UvCache::create(door.store(), door.lease())?;
    attempt(
        door,
        run,
        python,
        &retry_cache,
        false,
        run.capture,
        prepared,
    )
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

    /// A failed probe's private cache must not hide evidence in a later
    /// accepted run. The stand-in fails if that cache is reused, and the
    /// resulting receipt must carry permission for the metadata build.
    #[test]
    fn an_allowed_metadata_build_restarts_with_an_empty_cache_and_records_permission() {
        use std::os::unix::fs::PermissionsExt;
        let _serial = policy::attribution_test_lock();
        let Some(relay) = relay("uv-fresh-retry") else {
            return;
        };
        RELAY_FOR_TEST.with(|slot| *slot.borrow_mut() = Some(relay));
        let harness = Harness::new("uv-fresh-retry");
        let uv = Uv {
            obj: harness
                .store
                .stage_with_activity(&harness.activity)
                .unwrap(),
            runtime: harness
                .store
                .stage_with_activity(&harness.activity)
                .unwrap(),
            version: "test".into(),
        };
        fs::create_dir_all(uv.runtime.join("bin")).unwrap();
        fs::write(
            uv.binary(),
            r#"#!/bin/sh
case " $* " in
    *" --no-build "*)
        echo warmed > "$UV_CACHE_DIR/probe-metadata"
        echo 'error: Failed to build `local @ file:///project`' >&2
        echo 'Building source distributions for `local` is disabled' >&2
        exit 1
        ;;
esac
test ! -e "$UV_CACHE_DIR/probe-metadata" || exit 61
echo '# resolved in a fresh cache' > requirements.lock.txt
"#,
        )
        .unwrap();
        fs::set_permissions(uv.binary(), fs::Permissions::from_mode(0o755)).unwrap();
        let temp = TempDir::named("uv-retry-project");
        let held = ProjectRoot::open(&temp.0).unwrap();
        let spec =
            crate::tailors::record_spec(&super::super::tailor::Python, &held, uv.tool(), &["lock"])
                .unwrap();
        let slot = RecordSlot::default();
        let mut attribution = Attribution::open("python").unwrap();
        attribution
            .record(
                policy::RESOLUTION_BUILD,
                "setup.py",
                "cached setup metadata",
            )
            .unwrap();
        let mut door = ResolutionDoor::open(
            &harness.store,
            &harness.activity,
            Platform::host().unwrap(),
            DoorKind::Edit,
            &mut attribution,
        )
        .unwrap();
        let report = run_uv(
            &mut door,
            UvRun {
                uv: &uv,
                lock_root: &temp.0,
                cwd: None,
                args: vec!["lock".into()],
                index: Index::Project,
                outputs: super::super::resolve::resolution_outputs(&held).unwrap(),
                target: UvTarget::Project {
                    record: Some(spec),
                    slot: slot.clone(),
                },
                builds: Builds::Probe,
                capture: true,
                policy: Some(Policy::default()),
            },
        );
        drop(door);
        let recorded = attribution.recorded();
        attribution.discard();
        done();
        let report = report.unwrap();
        assert!(report.status.success(), "{}", stderr(&report));
        assert!(recorded
            .iter()
            .any(|fact| fact.kind == policy::RESOLUTION_BUILD));
        let (receipt, _) = slot.borrow_mut().take().unwrap();
        assert!(receipt
            .exceptions
            .iter()
            .any(|fact| fact.kind == policy::RESOLUTION_BUILD));
        assert!(receipt
            .exceptions
            .iter()
            .any(|fact| fact.kind == policy::RESOLUTION_BUILD && fact.subject == "setup.py"));
        assert!(temp.0.join("requirements.lock.txt").is_file());
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

    /// A local project's dynamic metadata is permission-gated before any
    /// backend runs, including its dynamic/transitive build dependencies.
    #[test]
    #[ignore = "realizes the store uv and CPython over the network"]
    fn the_projects_own_metadata_is_refused_before_running_a_backend() {
        let _serial = policy::attribution_test_lock();
        let label = "the_projects_own_metadata_is_refused_before_running_a_backend";
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
        assert!(error.contains("resolution-build: spike:"), "{error}");
        assert!(recorded.is_empty(), "{recorded:?}");
        assert!(!dir.join("uv.lock").exists());
        assert!(
            harness.upstream.seen().is_empty(),
            "a backend dependency was fetched"
        );
        // No metadata pre-step or build was allowed to run.
        let mut names: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        names.sort();
        assert_eq!(names, ["pyproject.toml", "spike"]);
    }
}

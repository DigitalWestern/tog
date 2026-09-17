//! `blanket audit` — the CI admission gate over recorded policy exceptions.
//!
//! Every sync records the exceptions it waved through in the project's
//! `.blanket/closures/<ecosystem>.json` (`body.exceptions[]`, kinds in
//! `policy::KINDS`). This module answers "would those closures pass policy
//! P?" from the records alone: no rebuild, no store access, no network, no
//! sandbox. It is read-only over the project directory (plus the same
//! read-only object-liveness probes `blanket status` makes).
//!
//! Two rules keep the answer honest:
//!
//! - A verdict is only computed over a record that still describes the
//!   project. Freshness reuses `inspect::closure_state`, the per-record
//!   check behind `blanket status`, applied to every closure file from its
//!   own body: a closure whose inputs changed, whose projection is missing,
//!   that was synced on another platform, or whose inputs are no longer
//!   found here is reported `stale`; one that predates input, platform, or
//!   exception recording is reported `unchecked`. Neither passes — an audit
//!   of a stale record proves nothing.
//! - The policy under test is the ordinary chain (`policy::load_with_sources`)
//!   unioned with the optional `--policy` file. Union only tightens, so the
//!   supplied policy can add denials but never remove what the machine or
//!   project policy says.
//! - An exception kind this binary does not know (a record written by a
//!   newer blanket, or by hand) is `unknown`, never permitted: no policy
//!   file can name it, so no policy file can be said to have allowed it.

use crate::cli;
use crate::commands::inspect::{self, ClosureFile, State};
use crate::commands::shared::project_dir;
use crate::kernel::platform::Platform;
use crate::kernel::policy::{self, Exception, Policy, PolicySource, SourceOrigin};
use crate::kernel::ui;
use crate::tailors;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io;
use std::path::Path;

/// Whether the record a verdict was computed over still describes the
/// project. Only `Current` records can pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Freshness {
    /// Recorded inputs match the files on disk and the projection is in place.
    Current,
    /// Inputs changed, projection missing, or synced on another platform.
    Stale(String),
    /// The record cannot be compared with the project (pre-field closure).
    Unchecked(String),
}

#[derive(Debug, Clone)]
pub struct Verdict {
    pub ecosystem: String,
    /// sha256 of the closure envelope bytes: the exact record audited.
    pub record_sha256: String,
    pub path: std::path::PathBuf,
    pub freshness: Freshness,
    /// Recorded exceptions the policy refuses, in recorded order.
    pub denied: Vec<Exception>,
    /// Recorded exceptions of a kind this binary does not know, in recorded
    /// order. Never permitted: the gate cannot judge them.
    pub unknown: Vec<Exception>,
    /// Recorded exceptions the policy permits, counted by kind.
    pub permitted: BTreeMap<String, usize>,
}

impl Verdict {
    /// Passes only when the record is current and no recorded exception is
    /// denied or unknown.
    pub fn passes(&self) -> bool {
        self.denied.is_empty() && self.unknown.is_empty() && self.freshness == Freshness::Current
    }
}

#[derive(Debug, Clone)]
pub struct Report {
    pub policy: Policy,
    /// The policies that were unioned into `policy`, in merge order, so the
    /// report can say which file denied a kind rather than only that
    /// something did.
    pub sources: Vec<PolicySource>,
    pub verdicts: Vec<Verdict>,
}

impl Report {
    pub fn passes(&self) -> bool {
        self.verdicts.iter().all(Verdict::passes)
    }
}

/// Read and validate a `--policy` file on its own, before it is unioned in,
/// so the dispatcher can report a missing or malformed file as a usage
/// error rather than a failed audit.
pub fn read_policy_file(path: &Path) -> io::Result<Policy> {
    let text = std::fs::read_to_string(path).map_err(|error| {
        io::Error::new(error.kind(), format!("read {}: {error}", path.display()))
    })?;
    policy::parse_file(path, &text)
}

/// The policy an audit judges against: the ordinary chain for `dir`
/// (BLANKET_POLICY or ~/.blanket/policy.toml, every ancestor's
/// .blanket/policy.toml, BLANKET_STRICT) unioned with `extra`, the parsed
/// `--policy` file and the path it came from. Union only tightens: `extra`
/// can add denials or strictness, never remove either. Returns the
/// contributing policies alongside the merged one, in merge order.
pub fn effective_policy(
    dir: &Path,
    extra: Option<(&Path, &Policy)>,
) -> io::Result<(Policy, Vec<PolicySource>)> {
    let (mut policy, mut sources) = policy::load_with_sources(dir, false)?;
    if let Some((path, extra)) = extra {
        policy::union(&mut policy, extra);
        sources.push(PolicySource::from_file(SourceOrigin::Flag, path, extra));
    }
    Ok((policy, sources))
}

/// Freshness of one closure file, from its own record. `present` is what
/// `inspect::detected` found in the directory: a closure for an ecosystem
/// whose inputs are gone describes a project that no longer exists here.
fn freshness(
    platform: Platform,
    dir: &Path,
    closure: &ClosureFile,
    present: &[&str],
) -> io::Result<Freshness> {
    // A closure is judged against the inputs of the ecosystem that owns it:
    // the `rustfmt` record `blanket fmt` writes belongs to a Cargo project.
    let owner = tailors::for_closure(&closure.ecosystem)
        .map(|tailor| tailor.id())
        .unwrap_or(closure.ecosystem.as_str());
    if !present.contains(&owner) {
        return Ok(Freshness::Stale(format!(
            "no {owner} inputs found here; the closure is orphaned"
        )));
    }
    if closure.platform.is_none() {
        // Envelopes without a platform predate the Linux port; `status`
        // cannot tell whether such a record was made on this host.
        return Ok(Freshness::Unchecked(
            "closure records no platform; run 'blanket sync' once to record it".into(),
        ));
    }
    Ok(freshness_from_state(inspect::closure_state(
        platform, dir, closure,
    )?))
}

/// The `status` state of a record, as the gate reads it: only `Synced` is
/// current; every other state fails.
fn freshness_from_state(state: State) -> Freshness {
    match state {
        State::Synced => Freshness::Current,
        State::NotSynced => Freshness::Stale("no closure for these inputs".into()),
        State::Changed(files) => {
            Freshness::Stale(format!("{} changed since the last sync", files.join(", ")))
        }
        State::ProjectionMissing(what) => {
            Freshness::Stale(format!("{what} is not the synced projection"))
        }
        State::ForeignPlatform(platform) => {
            Freshness::Stale(format!("synced on {platform}, not this host"))
        }
        State::Unchecked(why) => Freshness::Unchecked(why),
    }
}

/// A closure file must be named for the ecosystem it claims, as
/// `project::read_closure` requires; a mismatch is a record `sync` would
/// refuse, and the gate refuses it too rather than judging it under either
/// name.
fn check_name(closure: &ClosureFile) -> io::Result<()> {
    let stem = closure
        .path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or_default();
    if stem != closure.ecosystem {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{}: closure claims ecosystem '{}' but is named '{stem}'; a stray or renamed file under .blanket/closures is refused, not judged: remove it or run 'blanket sync'",
                closure.path.display(),
                closure.ecosystem
            ),
        ));
    }
    Ok(())
}

/// The recorded exceptions, or `None` when the closure carries no exception
/// record at all (absence is not evidence of a clean sync).
fn recorded_exceptions(closure: &ClosureFile) -> io::Result<Option<Vec<Exception>>> {
    match closure.body.get("exceptions") {
        None | Some(Value::Null) => Ok(None),
        Some(value) => serde_json::from_value(value.clone())
            .map(Some)
            .map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "{}: malformed exception record: {error}; run 'blanket sync'",
                        closure.path.display()
                    ),
                )
            }),
    }
}

/// Judge every closure file against `policy`, each from its own record.
/// `present` is what `inspect::detected` found in `dir`.
pub fn evaluate(
    platform: Platform,
    dir: &Path,
    policy: &Policy,
    closures: &[ClosureFile],
    present: &[&str],
) -> io::Result<Vec<Verdict>> {
    let mut verdicts = Vec::new();
    for closure in closures {
        check_name(closure)?;
        let mut freshness = freshness(platform, dir, closure, present)?;
        let mut denied = Vec::new();
        let mut unknown = Vec::new();
        let mut permitted = BTreeMap::new();
        match recorded_exceptions(closure)? {
            Some(exceptions) => {
                for exception in exceptions {
                    if !policy::KINDS.contains(&exception.kind.as_str()) {
                        unknown.push(exception);
                    } else if policy::denied(policy, &exception.kind) {
                        denied.push(exception);
                    } else {
                        *permitted.entry(exception.kind).or_insert(0) += 1;
                    }
                }
            }
            None => {
                if !matches!(freshness, Freshness::Stale(_)) {
                    freshness = Freshness::Unchecked(
                        "no exception record in this closure; run 'blanket sync' once to record one"
                            .into(),
                    );
                }
            }
        }
        verdicts.push(Verdict {
            ecosystem: closure.ecosystem.clone(),
            record_sha256: closure.record_sha256.clone(),
            path: closure.path.clone(),
            freshness,
            denied,
            unknown,
            permitted,
        });
    }
    Ok(verdicts)
}

/// Audit the project in `dir` under the policy chain unioned with `extra`
/// (an already-parsed `--policy` file). `Err(NotFound)` when nothing is
/// synced. Read-only: no store open, no lease, no process, no network.
pub fn audit(
    platform: Platform,
    dir: &Path,
    extra: Option<(&Path, &Policy)>,
) -> io::Result<Report> {
    let (policy, sources) = effective_policy(dir, extra)?;
    let closures = inspect::closures(dir)?;
    if closures.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "nothing synced in {}; run 'blanket sync' first",
                dir.display()
            ),
        ));
    }
    let present = inspect::detected(dir)?;
    let verdicts = evaluate(platform, dir, &policy, &closures, &present)?;
    Ok(Report {
        policy,
        sources,
        verdicts,
    })
}

/// One contributing policy as the text report shows it: origin, the file
/// (absent for strictness-only sources), and what it asked for.
fn source_line(source: &PolicySource) -> String {
    let mut line = format!("policy: {}", source.origin);
    if let Some(path) = &source.path {
        let lossy = path.to_string_lossy();
        line.push_str(&format!(" {:?}", lossy));
    }
    if !source.deny.is_empty() {
        line.push_str(&format!(
            " denies {}",
            source.deny.iter().cloned().collect::<Vec<_>>().join(", ")
        ));
    }
    if source.strict {
        line.push_str(" (strict)");
    }
    line
}

/// JSON cannot serialize a non-UTF-8 `PathBuf`. Keep the public policy model
/// platform-native, but make every report path an explicit lossy string. On
/// Unix, the byte field makes a lossy path reversible when its raw bytes are
/// not valid UTF-8.
struct JsonPath {
    lossy: String,
    bytes: Option<String>,
}

fn json_path(path: &Path) -> JsonPath {
    #[cfg(unix)]
    let bytes = {
        use std::os::unix::ffi::OsStrExt;

        path.to_str()
            .is_none()
            .then(|| hex::encode(path.as_os_str().as_bytes()))
    };
    #[cfg(not(unix))]
    let bytes = None;

    JsonPath {
        lossy: path.to_string_lossy().into_owned(),
        bytes,
    }
}

#[derive(serde::Serialize)]
struct JsonPolicySource {
    origin: SourceOrigin,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    path_bytes: Option<String>,
    strict: bool,
    deny: std::collections::BTreeSet<String>,
}

fn json_sources(sources: &[PolicySource]) -> Vec<JsonPolicySource> {
    sources
        .iter()
        .map(|source| {
            let path = source.path.as_deref().map(json_path);
            JsonPolicySource {
                origin: source.origin,
                path: path.as_ref().map(|path| path.lossy.clone()),
                path_bytes: path.and_then(|path| path.bytes),
                strict: source.strict,
                deny: source.deny.clone(),
            }
        })
        .collect()
}

pub fn render(dir: &Path, report: &Report, json: bool) -> io::Result<String> {
    if json {
        let JsonPath {
            lossy: project,
            bytes: project_bytes,
        } = json_path(dir);
        let closures = report
            .verdicts
            .iter()
            .map(|verdict| {
                let JsonPath {
                    lossy: path,
                    bytes: path_bytes,
                } = json_path(&verdict.path);
                let (freshness, detail): (&str, Value) = match &verdict.freshness {
                    Freshness::Current => ("current", Value::Null),
                    Freshness::Stale(why) => ("stale", json!(why)),
                    Freshness::Unchecked(why) => ("unchecked", json!(why)),
                };
                let mut closure = json!({
                    "ecosystem": verdict.ecosystem,
                    "record_sha256": verdict.record_sha256,
                    "path": path,
                    "passed": verdict.passes(),
                    "freshness": freshness,
                    "freshness_detail": detail,
                    "denied": verdict.denied,
                    "unknown": verdict.unknown,
                    "permitted": verdict.permitted,
                });
                if let Some(path_bytes) = path_bytes {
                    closure["path_bytes"] = json!(path_bytes);
                }
                closure
            })
            .collect::<Vec<_>>();
        let value = json!({
            "project": project,
            "policy": {
                "strict": report.policy.strict,
                "deny": report.policy.deny,
                "sources": json_sources(&report.sources),
            },
            "passed": report.passes(),
            "closures": closures,
        });
        let mut value = value;
        if let Some(project_bytes) = project_bytes {
            value["project_bytes"] = json!(project_bytes);
        }
        return Ok(serde_json::to_string_pretty(&value)? + "\n");
    }
    let width = report
        .verdicts
        .iter()
        .map(|verdict| verdict.ecosystem.len())
        .max()
        .unwrap_or(0);
    let mut out = String::new();
    // Policy provenance is a report result on stdout. Keep it before the
    // verdicts, and do not suppress it with `--quiet`.
    for source in &report.sources {
        out.push_str(&source_line(source));
        out.push('\n');
    }
    for verdict in &report.verdicts {
        let record = &verdict.record_sha256[..16];
        let permitted = if verdict.permitted.is_empty() {
            "no exceptions".to_string()
        } else {
            verdict
                .permitted
                .iter()
                .map(|(kind, count)| format!("{kind} {count}"))
                .collect::<Vec<_>>()
                .join(", ")
        };
        // What the policy says about the record's exceptions, independent
        // of whether the record is current; shown on every line so a stale
        // record's denials are not hidden behind its staleness.
        let judged = match (verdict.denied.len(), verdict.unknown.len()) {
            (0, 0) => format!("permitted: {permitted}"),
            (denied, 0) => format!("{denied} denied; permitted: {permitted}"),
            (0, unknown) => format!("{unknown} of unknown kind; permitted: {permitted}"),
            (denied, unknown) => {
                format!("{denied} denied, {unknown} of unknown kind; permitted: {permitted}")
            }
        };
        let line = match &verdict.freshness {
            Freshness::Stale(why) => format!(
                "stale      closure {record}: {why}; run 'blanket sync', then audit again ({judged})"
            ),
            Freshness::Unchecked(why) => format!("unchecked  closure {record}: {why} ({judged})"),
            _ if !verdict.denied.is_empty() => format!("denied     closure {record}: {judged}"),
            _ if !verdict.unknown.is_empty() => format!("unknown    closure {record}: {judged}"),
            _ => format!("clean      closure {record}: {judged}"),
        };
        out.push_str(&format!("{:width$}  {line}\n", verdict.ecosystem));
        for exception in &verdict.denied {
            out.push_str(&format!(
                "{:width$}    denied   {}  {}  {}\n",
                "", exception.kind, exception.subject, exception.detail
            ));
        }
        for exception in &verdict.unknown {
            out.push_str(&format!(
                "{:width$}    unknown  {}  {}  {}\n",
                "", exception.kind, exception.subject, exception.detail
            ));
        }
    }
    Ok(out)
}

/// The command: judge the recorded exceptions against the policy chain plus
/// an optional `--policy` file. Needs the host platform only to tell a
/// foreign-platform closure from a current one, as `status` does.
pub fn run(policy: Option<&Path>, json: bool) -> io::Result<i32> {
    let platform = Platform::host()?;
    let dir = project_dir();
    // A --policy file that cannot be read or parsed is an operator
    // mistake (exit 2), so CI can tell it from a denied build (exit 1).
    let extra = match policy {
        Some(path) => match read_policy_file(path) {
            Ok(extra) => Some((path, extra)),
            Err(error) => {
                eprint!(
                    "{}",
                    cli::render_usage_error(&format!("audit: {error}"), Some("audit"))
                );
                return Ok(cli::EXIT_USAGE);
            }
        },
        None => None,
    };
    let report = audit(
        platform,
        &dir,
        extra.as_ref().map(|(path, extra)| (*path, extra)),
    )?;
    ui::note(&format!(
        "audit: policy strict={} deny=[{}]",
        report.policy.strict,
        report
            .policy
            .deny
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .join(", ")
    ));
    print!("{}", render(&dir, &report, json)?);
    Ok(if report.passes() {
        0
    } else {
        cli::EXIT_FAILURE
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::policy::{
        GIT_DEPENDENCY, INSTALL_SCRIPT_FAILED, SKIPPED_OPTIONAL, WEAK_INTEGRITY,
    };
    use crate::tailors::cargo::rustfmt;
    use std::collections::BTreeSet;
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::ffi::OsStringExt;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "blanket-audit-{label}-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn host() -> Platform {
        Platform::host().unwrap()
    }

    fn exception(kind: &str, subject: &str) -> Exception {
        Exception {
            kind: kind.into(),
            subject: subject.into(),
            detail: format!("{kind} on {subject}"),
        }
    }

    /// A python project with a projection and recorded inputs, so a closure
    /// written by `python_closure` is current until `requirements.txt`
    /// changes.
    fn python_project(label: &str) -> TempDir {
        let temp = TempDir::new(label);
        let dir = &temp.0;
        fs::write(dir.join("requirements.txt"), "six==1.17.0\n").unwrap();
        let env = dir.join("env-object");
        fs::create_dir_all(env.join("bin")).unwrap();
        std::os::unix::fs::symlink(&env, dir.join(".venv")).unwrap();
        temp
    }

    /// The body `python_project`'s closure needs to be current.
    fn python_body(dir: &Path) -> Value {
        json!({
            "env_object": dir.join("env-object"),
            "python": {"version": "3.12.14"},
            "plan": {"packages": []},
            "inputs": [{
                "path": "requirements.txt",
                "sha256": inspect::sha256_file(&dir.join("requirements.txt")).unwrap(),
            }],
        })
    }

    /// The body `blanket fmt` writes for `dir` with this binary's pins: a
    /// current `rustfmt` record once `dir` holds Cargo inputs.
    fn rustfmt_body(dir: &Path) -> Value {
        let mut body = rustfmt::pinned_record(host(), dir).unwrap();
        body["exceptions"] = json!([]);
        body
    }

    /// Write `.blanket/closures/<name>.json` and return it as `closures`
    /// would read it.
    fn write_closure(
        dir: &Path,
        name: &str,
        ecosystem: &str,
        platform: Option<&str>,
        body: Value,
    ) -> ClosureFile {
        let closures = dir.join(".blanket/closures");
        fs::create_dir_all(&closures).unwrap();
        let mut envelope = json!({
            "schema": "closure/1",
            "ecosystem": ecosystem,
            "projected_at": 1,
            "body": body,
        });
        if let Some(platform) = platform {
            envelope["platform"] = json!(platform);
        }
        let path = closures.join(format!("{name}.json"));
        fs::write(&path, serde_json::to_vec_pretty(&envelope).unwrap()).unwrap();
        inspect::closures(dir)
            .unwrap()
            .into_iter()
            .find(|closure| closure.path == path)
            .unwrap()
    }

    fn with_exceptions(dir: &Path, exceptions: &[Exception]) -> ClosureFile {
        let mut body = python_body(dir);
        body["exceptions"] = serde_json::to_value(exceptions).unwrap();
        write_closure(dir, "python", "python", Some(host().triple()), body)
    }

    fn deny(kinds: &[&str]) -> Policy {
        Policy {
            strict: false,
            deny: kinds.iter().map(|kind| kind.to_string()).collect(),
        }
    }

    fn judge(dir: &Path, policy: &Policy, closures: &[ClosureFile]) -> Vec<Verdict> {
        let present = inspect::detected(dir).unwrap();
        evaluate(host(), dir, policy, closures, &present).unwrap()
    }

    fn record(verdict: &Verdict) -> String {
        verdict.record_sha256[..16].to_string()
    }

    #[test]
    fn clean_when_every_recorded_exception_is_permitted() {
        let temp = python_project("clean");
        let closures = [with_exceptions(
            &temp.0,
            &[
                exception(SKIPPED_OPTIONAL, "dev"),
                exception(SKIPPED_OPTIONAL, "docs"),
            ],
        )];
        let verdicts = judge(&temp.0, &deny(&[GIT_DEPENDENCY]), &closures);
        assert_eq!(verdicts.len(), 1);
        assert!(verdicts[0].passes());
        assert!(verdicts[0].denied.is_empty());
        assert!(verdicts[0].unknown.is_empty());
        assert_eq!(verdicts[0].permitted.get(SKIPPED_OPTIONAL), Some(&2));
        assert_eq!(verdicts[0].freshness, Freshness::Current);
        assert_eq!(verdicts[0].record_sha256.len(), 64);
        let record = record(&verdicts[0]);
        let report = Report {
            policy: deny(&[GIT_DEPENDENCY]),
            sources: Vec::new(),
            verdicts,
        };
        assert!(report.passes());
        let text = render(&temp.0, &report, false).unwrap();
        assert_eq!(
            text,
            format!("python  clean      closure {record}: permitted: skipped_optional 2\n")
        );
        let value: Value = serde_json::from_str(&render(&temp.0, &report, true).unwrap()).unwrap();
        assert_eq!(value["passed"], true);
        assert_eq!(value["closures"][0]["passed"], true);
        assert_eq!(value["closures"][0]["freshness"], "current");
        assert_eq!(value["closures"][0]["permitted"][SKIPPED_OPTIONAL], 2);
        assert_eq!(
            value["closures"][0]["record_sha256"]
                .as_str()
                .unwrap()
                .len(),
            64
        );
        assert_eq!(value["policy"]["deny"][0], GIT_DEPENDENCY);
        assert_eq!(value["policy"]["strict"], false);
    }

    /// A report is the conjunction of its verdicts, not the disjunction:
    /// one failing closure fails the whole audit however many clean ones
    /// sit beside it, and in either order. Every other test here judges a
    /// single closure, where "all pass" and "any passes" agree.
    #[test]
    fn one_failing_closure_fails_the_whole_report() {
        let temp = python_project("mixed");
        let dir = &temp.0;
        fs::write(dir.join("Cargo.toml"), "[package]\nname = \"mixed\"\n").unwrap();
        let clean = write_closure(
            dir,
            "rustfmt",
            "rustfmt",
            Some(host().triple()),
            rustfmt_body(dir),
        );
        let failing = with_exceptions(dir, &[exception(GIT_DEPENDENCY, "left-pad")]);
        let policy = deny(&[GIT_DEPENDENCY]);
        for closures in [
            vec![clean.clone(), failing.clone()],
            vec![failing, clean.clone()],
        ] {
            let verdicts = judge(dir, &policy, &closures);
            assert_eq!(
                verdicts.iter().filter(|verdict| verdict.passes()).count(),
                1,
                "{verdicts:?}"
            );
            let report = Report {
                policy: policy.clone(),
                sources: Vec::new(),
                verdicts,
            };
            assert!(!report.passes(), "one denied closure must fail the report");
            let value: Value = serde_json::from_str(&render(dir, &report, true).unwrap()).unwrap();
            assert_eq!(value["passed"], false);
        }
        // Not vacuous: the same machinery passes when every verdict does.
        let report = Report {
            policy: policy.clone(),
            sources: Vec::new(),
            verdicts: judge(dir, &policy, &[clean.clone(), clean]),
        };
        assert!(report.passes());
    }

    #[cfg(unix)]
    #[test]
    fn json_policy_source_lossily_serializes_non_utf8_paths() {
        let path = PathBuf::from(std::ffi::OsString::from_vec(vec![
            b'p', b'o', b'l', b'i', b'c', b'y', b'-', 0xff, b'.', b't', b'o', b'm', b'l',
        ]));
        let report = Report {
            policy: Policy::default(),
            sources: vec![PolicySource {
                origin: SourceOrigin::Machine,
                path: Some(path),
                strict: false,
                deny: BTreeSet::new(),
            }],
            verdicts: Vec::new(),
        };

        let output = render(Path::new("project"), &report, true).unwrap();
        let value: Value = serde_json::from_str(&output).unwrap();
        assert_eq!(
            value["policy"]["sources"][0]["path"],
            "policy-\u{fffd}.toml"
        );
        assert_eq!(
            value["policy"]["sources"][0]["path_bytes"],
            "706f6c6963792dff2e746f6d6c"
        );

        let output = render(Path::new("project"), &report, false).unwrap();
        assert_eq!(output, "policy: machine \"policy-\u{fffd}.toml\"\n");
    }

    #[test]
    fn text_policy_source_quotes_control_characters_in_paths() {
        let report = Report {
            policy: Policy::default(),
            sources: vec![PolicySource {
                origin: SourceOrigin::Machine,
                path: Some(PathBuf::from("policy-\n.toml")),
                strict: false,
                deny: BTreeSet::new(),
            }],
            verdicts: Vec::new(),
        };

        let output = render(Path::new("project"), &report, false).unwrap();
        assert_eq!(output, "policy: machine \"policy-\\n.toml\"\n");
    }

    #[test]
    fn text_policy_source_quotes_grammar_significant_paths() {
        let temp = TempDir::new("quoted-policy");
        let path = temp.0.join("policy denies git-dependency (strict).toml");
        fs::write(&path, "strict = true\ndeny = [\"git-dependency\"]\n").unwrap();
        let policy = read_policy_file(&path).unwrap();
        let report = Report {
            policy: policy.clone(),
            sources: vec![PolicySource::from_file(SourceOrigin::Flag, &path, &policy)],
            verdicts: Vec::new(),
        };

        let output = render(Path::new("project"), &report, false).unwrap();
        assert_eq!(
            output,
            format!(
                "policy: flag {:?} denies git-dependency (strict)\n",
                path.to_string_lossy()
            )
        );
    }

    #[test]
    fn denied_exceptions_are_listed_with_subject_and_detail() {
        let temp = python_project("denied");
        let closures = [with_exceptions(
            &temp.0,
            &[
                exception(INSTALL_SCRIPT_FAILED, "sharp@0.33.0"),
                exception(SKIPPED_OPTIONAL, "fsevents"),
                exception(WEAK_INTEGRITY, "left-pad@1.0.0"),
            ],
        )];
        let policy = deny(&[INSTALL_SCRIPT_FAILED, WEAK_INTEGRITY]);
        let verdicts = judge(&temp.0, &policy, &closures);
        assert!(!verdicts[0].passes());
        assert_eq!(
            verdicts[0].denied,
            vec![
                exception(INSTALL_SCRIPT_FAILED, "sharp@0.33.0"),
                exception(WEAK_INTEGRITY, "left-pad@1.0.0"),
            ]
        );
        assert_eq!(verdicts[0].permitted.get(SKIPPED_OPTIONAL), Some(&1));
        let record = record(&verdicts[0]);
        let report = Report {
            policy,
            sources: Vec::new(),
            verdicts,
        };
        assert!(!report.passes());
        let text = render(&temp.0, &report, false).unwrap();
        assert!(
            text.contains(&format!(
                "python  denied     closure {record}: 2 denied; permitted: skipped_optional 1\n"
            )),
            "{text}"
        );
        assert!(
            text.contains("    denied   install-script-failed  sharp@0.33.0  install-script-failed on sharp@0.33.0\n"),
            "{text}"
        );
        let value: Value = serde_json::from_str(&render(&temp.0, &report, true).unwrap()).unwrap();
        assert_eq!(value["passed"], false);
        assert_eq!(value["closures"][0]["denied"][1]["kind"], WEAK_INTEGRITY);
        assert_eq!(
            value["closures"][0]["denied"][1]["subject"],
            "left-pad@1.0.0"
        );
    }

    #[test]
    fn strict_policy_denies_every_kind() {
        let temp = python_project("strict");
        let closures = [with_exceptions(
            &temp.0,
            &[exception(SKIPPED_OPTIONAL, "dev")],
        )];
        let strict = Policy {
            strict: true,
            deny: BTreeSet::new(),
        };
        let verdicts = judge(&temp.0, &strict, &closures);
        assert_eq!(verdicts[0].denied.len(), 1);
        assert!(!verdicts[0].passes());
    }

    #[test]
    fn unknown_kind_is_never_permitted_and_no_policy_can_name_it() {
        let temp = python_project("unknown");
        let closures = [with_exceptions(
            &temp.0,
            &[
                exception("kind-from-a-newer-blanket", "left-pad"),
                exception(SKIPPED_OPTIONAL, "dev"),
            ],
        )];
        // Neither an empty policy nor one that denies everything it knows
        // permits it; only strict catches it, by denying everything.
        for policy in [Policy::default(), deny(policy::KINDS)] {
            let verdicts = judge(&temp.0, &policy, &closures);
            assert!(!verdicts[0].passes(), "{policy:?}");
            assert_eq!(
                verdicts[0].unknown,
                vec![exception("kind-from-a-newer-blanket", "left-pad")]
            );
            assert!(!verdicts[0]
                .permitted
                .contains_key("kind-from-a-newer-blanket"));
        }
        let verdicts = judge(&temp.0, &Policy::default(), &closures);
        assert!(verdicts[0].denied.is_empty());
        let record = record(&verdicts[0]);
        let report = Report {
            policy: Policy::default(),
            sources: Vec::new(),
            verdicts,
        };
        let text = render(&temp.0, &report, false).unwrap();
        assert!(
            text.contains(&format!(
                "python  unknown    closure {record}: 1 of unknown kind; permitted: skipped_optional 1\n"
            )),
            "{text}"
        );
        assert!(
            text.contains("    unknown  kind-from-a-newer-blanket  left-pad  "),
            "{text}"
        );
        let value: Value = serde_json::from_str(&render(&temp.0, &report, true).unwrap()).unwrap();
        assert_eq!(value["passed"], false);
        assert_eq!(
            value["closures"][0]["unknown"][0]["kind"],
            "kind-from-a-newer-blanket"
        );
        // And a policy file cannot name it, so it cannot be "allowed" either.
        assert!(policy::parse_file(
            Path::new("p.toml"),
            "deny = [\"kind-from-a-newer-blanket\"]"
        )
        .is_err());
    }

    #[test]
    fn extra_policy_denies_what_the_chain_permits() {
        let temp = python_project("extra");
        let extra = temp.0.join("company.toml");
        fs::write(&extra, "deny = [\"install-script-failed\"]\n").unwrap();
        let closures = [with_exceptions(
            &temp.0,
            &[exception(INSTALL_SCRIPT_FAILED, "sharp@0.33.0")],
        )];
        let mut chain = Policy::default();
        assert!(judge(&temp.0, &chain, &closures)[0].passes());
        policy::union(&mut chain, &read_policy_file(&extra).unwrap());
        let verdicts = judge(&temp.0, &chain, &closures);
        assert!(!verdicts[0].passes());
        assert_eq!(verdicts[0].denied[0].kind, INSTALL_SCRIPT_FAILED);
    }

    #[test]
    fn extra_policy_cannot_loosen_the_chain() {
        let temp = python_project("loosen");
        let extra = temp.0.join("permissive.toml");
        fs::write(&extra, "strict = false\ndeny = []\n").unwrap();
        let closures = [with_exceptions(
            &temp.0,
            &[exception(GIT_DEPENDENCY, "left-pad")],
        )];
        let permissive = read_policy_file(&extra).unwrap();
        let mut chain = deny(&[GIT_DEPENDENCY]);
        policy::union(&mut chain, &permissive);
        assert!(chain.deny.contains(GIT_DEPENDENCY));
        assert!(!judge(&temp.0, &chain, &closures)[0].passes());
        // Nor can it lift strict.
        let mut strict = Policy {
            strict: true,
            deny: BTreeSet::new(),
        };
        policy::union(&mut strict, &permissive);
        assert!(strict.strict);
        // A file with an unknown kind is refused, not silently ignored; so
        // is a missing one, so the gate never runs under a policy the
        // caller did not get.
        fs::write(&extra, "deny = [\"typo\"]\n").unwrap();
        assert!(read_policy_file(&extra).is_err());
        assert!(read_policy_file(&temp.0.join("absent.toml")).is_err());
    }

    #[test]
    fn effective_policy_unions_the_project_chain_with_the_extra_file() {
        // The chain also reads BLANKET_POLICY or $HOME, which other tests
        // and the developer's machine own; assert only that this project's
        // ancestor policy and the extra file both land (superset), never
        // that nothing else did.
        let temp = python_project("chain");
        let root = temp.0.join("workspace");
        let member = root.join("member");
        fs::create_dir_all(root.join(".blanket")).unwrap();
        fs::create_dir_all(&member).unwrap();
        fs::write(
            root.join(".blanket/policy.toml"),
            "deny = [\"weak-integrity\"]\n",
        )
        .unwrap();
        let extra = Policy {
            strict: false,
            deny: [GIT_DEPENDENCY.to_string()].into_iter().collect(),
        };
        let policy_file = temp.0.join("company.toml");
        let _env = policy::test_env_lock();
        let (policy, sources) =
            effective_policy(&member, Some((policy_file.as_path(), &extra))).unwrap();
        assert!(policy.deny.contains(WEAK_INTEGRITY));
        assert!(policy.deny.contains(GIT_DEPENDENCY));
        // Each denial is attributable: the workspace root asked for one, the
        // --policy file for the other, and that source is merged last.
        let ancestor = sources
            .iter()
            .find(|source| {
                source.path.as_deref() == Some(root.join(".blanket/policy.toml").as_path())
            })
            .expect("the workspace-root policy is a source");
        assert_eq!(ancestor.origin, SourceOrigin::Project);
        assert!(ancestor.deny.contains(WEAK_INTEGRITY));
        let last = sources.last().expect("the --policy file is a source");
        assert_eq!(last.origin, SourceOrigin::Flag);
        assert_eq!(last.path, Some(policy_file));
        assert!(last.deny.contains(GIT_DEPENDENCY));
        let (without, sources) = effective_policy(&member, None).unwrap();
        assert!(without.deny.contains(WEAK_INTEGRITY));
        assert!(!sources
            .iter()
            .any(|source| source.origin == SourceOrigin::Flag));
        // A file that does not exist is not a source: the member directory
        // has no policy of its own.
        assert!(!sources.iter().any(|source| {
            source.path.as_deref() == Some(member.join(".blanket/policy.toml").as_path())
        }));
    }

    #[test]
    fn stale_closure_never_audits_clean() {
        let temp = python_project("stale");
        let dir = &temp.0;
        // Inputs changed since the record was written.
        let closures = [with_exceptions(dir, &[])];
        fs::write(dir.join("requirements.txt"), "six==1.16.0\n").unwrap();
        let verdicts = judge(dir, &Policy::default(), &closures);
        assert_eq!(
            verdicts[0].freshness,
            Freshness::Stale("requirements.txt changed since the last sync".into())
        );
        assert!(!verdicts[0].passes());
        // Projection missing.
        fs::write(dir.join("requirements.txt"), "six==1.17.0\n").unwrap();
        fs::remove_file(dir.join(".venv")).unwrap();
        let verdicts = judge(dir, &Policy::default(), &closures);
        assert_eq!(
            verdicts[0].freshness,
            Freshness::Stale(".venv is not the synced projection".into())
        );
        assert!(!verdicts[0].passes());
        std::os::unix::fs::symlink(dir.join("env-object"), dir.join(".venv")).unwrap();
        // Synced on another platform.
        let mut body = python_body(dir);
        body["exceptions"] = json!([]);
        let foreign = [write_closure(
            dir,
            "python",
            "python",
            Some("other-platform"),
            body,
        )];
        let verdicts = judge(dir, &Policy::default(), &foreign);
        assert_eq!(
            verdicts[0].freshness,
            Freshness::Stale("synced on other-platform, not this host".into())
        );
        assert!(!verdicts[0].passes());
        // Inputs gone from the directory: the closure is orphaned.
        let closures = [with_exceptions(dir, &[])];
        fs::remove_file(dir.join("requirements.txt")).unwrap();
        let verdicts = judge(dir, &Policy::default(), &closures);
        assert_eq!(
            verdicts[0].freshness,
            Freshness::Stale("no python inputs found here; the closure is orphaned".into())
        );
        assert!(!verdicts[0].passes());
        let record = record(&verdicts[0]);
        let report = Report {
            policy: Policy::default(),
            sources: Vec::new(),
            verdicts,
        };
        assert!(!report.passes());
        let text = render(dir, &report, false).unwrap();
        assert!(
            text.contains(&format!(
                "python  stale      closure {record}: no python inputs"
            )),
            "{text}"
        );
        assert!(
            text.contains("run 'blanket sync', then audit again (permitted: no exceptions)"),
            "{text}"
        );
        let value: Value = serde_json::from_str(&render(dir, &report, true).unwrap()).unwrap();
        assert_eq!(value["passed"], false);
        assert_eq!(value["closures"][0]["freshness"], "stale");
        // A stale record's denials are still shown, not hidden behind the
        // staleness.
        fs::write(dir.join("requirements.txt"), "six==1.17.0\n").unwrap();
        let closures = [with_exceptions(
            dir,
            &[exception(GIT_DEPENDENCY, "left-pad")],
        )];
        fs::write(dir.join("requirements.txt"), "six==1.16.0\n").unwrap();
        let verdicts = judge(dir, &deny(&[GIT_DEPENDENCY]), &closures);
        assert!(matches!(verdicts[0].freshness, Freshness::Stale(_)));
        assert_eq!(verdicts[0].denied.len(), 1);
        let report = Report {
            policy: deny(&[GIT_DEPENDENCY]),
            sources: Vec::new(),
            verdicts,
        };
        let text = render(dir, &report, false).unwrap();
        assert!(
            text.contains("(1 denied; permitted: no exceptions)"),
            "{text}"
        );
        assert!(
            text.contains("    denied   git-dependency  left-pad"),
            "{text}"
        );
    }

    #[test]
    fn every_status_state_but_synced_fails() {
        // The mapping the gate applies to a record's `status` state:
        // `NotSynced` is unreachable per record, and must still not pass.
        assert_eq!(freshness_from_state(State::Synced), Freshness::Current);
        for state in [
            State::NotSynced,
            State::Changed(vec!["a".into()]),
            State::ProjectionMissing("x".into()),
            State::ForeignPlatform("p".into()),
            State::Unchecked("why".into()),
        ] {
            let freshness = freshness_from_state(state.clone());
            // Exhaustive on purpose (no `_` arm): a new `State` variant must
            // fail to compile here, not silently skip the mapping check.
            match state {
                State::Synced => unreachable!("asserted above, outside the loop"),
                State::Unchecked(_) => assert!(matches!(freshness, Freshness::Unchecked(_))),
                State::NotSynced
                | State::Changed(_)
                | State::ProjectionMissing(_)
                | State::ForeignPlatform(_) => {
                    assert!(matches!(freshness, Freshness::Stale(_)), "{state:?}")
                }
            }
            let verdict = Verdict {
                ecosystem: "python".into(),
                record_sha256: "0".repeat(64),
                path: PathBuf::from("python.json"),
                freshness,
                denied: Vec::new(),
                unknown: Vec::new(),
                permitted: BTreeMap::new(),
            };
            assert!(!verdict.passes(), "{verdict:?}");
        }
    }

    #[test]
    fn unchecked_closure_is_reported_unchecked_not_clean() {
        let temp = python_project("unchecked");
        let dir = &temp.0;
        // Pre-field closure: no recorded inputs, status says synced (unchecked).
        let mut body = python_body(dir);
        body.as_object_mut().unwrap().remove("inputs");
        body["exceptions"] = json!([]);
        let closures = [write_closure(
            dir,
            "python",
            "python",
            Some(host().triple()),
            body,
        )];
        assert_eq!(
            inspect::closure_state(host(), dir, &closures[0]).unwrap(),
            State::Unchecked(
                "inputs were not recorded by this sync; run 'blanket sync' once to enable checks"
                    .into()
            )
        );
        let verdicts = judge(dir, &Policy::default(), &closures);
        assert!(
            matches!(verdicts[0].freshness, Freshness::Unchecked(ref why) if why.contains("inputs were not recorded")),
            "{:?}",
            verdicts[0]
        );
        assert!(!verdicts[0].passes());
        // No recorded platform: status cannot tell which host made it.
        let mut body = python_body(dir);
        body["exceptions"] = json!([]);
        let closures = [write_closure(dir, "python", "python", None, body)];
        let verdicts = judge(dir, &Policy::default(), &closures);
        assert!(
            matches!(verdicts[0].freshness, Freshness::Unchecked(ref why) if why.contains("records no platform")),
            "{:?}",
            verdicts[0]
        );
        assert!(!verdicts[0].passes());
        // A current closure without an exception record is unchecked too:
        // absence of the record is not evidence of a clean sync.
        let closures = [write_closure(
            dir,
            "python",
            "python",
            Some(host().triple()),
            python_body(dir),
        )];
        let verdicts = judge(dir, &Policy::default(), &closures);
        assert!(
            matches!(verdicts[0].freshness, Freshness::Unchecked(ref why) if why.contains("no exception record")),
            "{:?}",
            verdicts[0]
        );
        assert!(!verdicts[0].passes());
        let record = record(&verdicts[0]);
        let report = Report {
            policy: Policy::default(),
            sources: Vec::new(),
            verdicts,
        };
        let text = render(dir, &report, false).unwrap();
        assert!(
            text.contains(&format!(
                "python  unchecked  closure {record}: no exception record"
            )),
            "{text}"
        );
        let value: Value = serde_json::from_str(&render(dir, &report, true).unwrap()).unwrap();
        assert_eq!(value["closures"][0]["freshness"], "unchecked");
        assert_eq!(value["passed"], false);
        // A stale closure without a record stays stale (the stronger verdict).
        fs::write(dir.join("requirements.txt"), "six==1.16.0\n").unwrap();
        let verdicts = judge(dir, &Policy::default(), &closures);
        assert!(matches!(verdicts[0].freshness, Freshness::Stale(_)));
    }

    /// `blanket fmt` projects nothing, so its record is compared with the
    /// pins: current only when it names the rustfmt this binary would use
    /// for the project, and judged on its exceptions like any other record.
    #[test]
    fn rustfmt_record_is_compared_with_its_pin() {
        let temp = TempDir::new("rustfmt");
        let dir = &temp.0;
        fs::write(dir.join("Cargo.toml"), "[package]\nname = \"fmt\"\n").unwrap();
        let write = |body: Value| {
            [write_closure(
                dir,
                "rustfmt",
                "rustfmt",
                Some(host().triple()),
                body,
            )]
        };

        // Current: passes, and its exceptions are still judged.
        let mut body = rustfmt_body(dir);
        body["exceptions"] = json!([exception(policy::TOOLCHAIN_COMPONENT_UNAVAILABLE, "clippy")]);
        let closures = write(body.clone());
        let verdicts = judge(dir, &Policy::default(), &closures);
        assert_eq!(verdicts[0].freshness, Freshness::Current, "{verdicts:?}");
        assert!(verdicts[0].passes());
        let verdicts = judge(
            dir,
            &deny(&[policy::TOOLCHAIN_COMPONENT_UNAVAILABLE]),
            &closures,
        );
        assert!(!verdicts[0].passes());

        // Made by another rustfmt version: stale, naming both objects.
        let current = body["rustfmt_object"]["id"].as_str().unwrap().to_string();
        let older = format!("{}-rustfmt-1.95.0", "0".repeat(40));
        let mut stale = body.clone();
        stale["inputs"] = rustfmt::record_inputs(&older);
        stale["rustfmt_object"]["id"] = json!(older);
        stale["rust_version"] = json!("1.95.0");
        let verdicts = judge(dir, &Policy::default(), &write(stale));
        let Freshness::Stale(why) = &verdicts[0].freshness else {
            panic!("{verdicts:?}");
        };
        assert!(why.contains(&older) && why.contains(&current), "{why}");
        assert!(!verdicts[0].passes());

        // Same version, another component pin: the id differs, so stale.
        let mut repinned = body.clone();
        let other = format!("{}-rustfmt-1.96.1", "1".repeat(40));
        repinned["inputs"] = rustfmt::record_inputs(&other);
        let verdicts = judge(dir, &Policy::default(), &write(repinned));
        assert!(matches!(verdicts[0].freshness, Freshness::Stale(_)));

        // Inputs that match but a body naming another object: stale, so the
        // object `ls`, `sbom`, and `gc` read is the one audited.
        for (field, value) in [
            ("rustfmt_object", json!({"id": "other-rustfmt"})),
            ("rust_object", json!({"id": "other-rust"})),
            ("rust_version", json!("1.95.0")),
        ] {
            let mut forged = body.clone();
            forged[field] = value;
            let verdicts = judge(dir, &Policy::default(), &write(forged));
            assert!(
                matches!(&verdicts[0].freshness, Freshness::Stale(why) if why.contains(field)),
                "{field}: {verdicts:?}"
            );
        }

        // An inputs-free record from before inputs were recorded: unchecked.
        let mut old = body.clone();
        old.as_object_mut().unwrap().remove("inputs");
        let verdicts = judge(dir, &Policy::default(), &write(old));
        let report = Report {
            policy: Policy::default(),
            sources: Vec::new(),
            verdicts,
        };
        assert!(
            matches!(&report.verdicts[0].freshness, Freshness::Unchecked(why) if why.contains("blanket fmt")),
            "{:?}",
            report.verdicts[0]
        );
        assert!(!report.passes());
        let value: Value = serde_json::from_str(&render(dir, &report, true).unwrap()).unwrap();
        assert_eq!(value["closures"][0]["freshness"], "unchecked");

        // A python-shaped record under the rustfmt name is compared the same
        // way; the name alone buys nothing.
        fs::write(dir.join("requirements.txt"), "six==1.17.0\n").unwrap();
        let mut python = python_body(dir);
        python["exceptions"] = json!([]);
        let verdicts = judge(dir, &Policy::default(), &write(python));
        assert!(matches!(verdicts[0].freshness, Freshness::Stale(_)));

        // A toolchain file that lists rustfmt: `sync` would record an
        // exception, but the read-only comparison records nothing and still
        // resolves the same pin.
        fs::write(
            dir.join("rust-toolchain.toml"),
            "[toolchain]\nchannel = \"stable\"\ncomponents = [\"rustfmt\", \"clippy\"]\n",
        )
        .unwrap();
        let verdicts = judge(dir, &Policy::default(), &write(body.clone()));
        assert_eq!(verdicts[0].freshness, Freshness::Current, "{verdicts:?}");

        // A toolchain this binary pins no rustfmt for: stale, not an error.
        fs::write(
            dir.join("rust-toolchain.toml"),
            "[toolchain]\nchannel = \"1.2\"\n",
        )
        .unwrap();
        let verdicts = judge(dir, &Policy::default(), &write(body.clone()));
        assert!(
            matches!(&verdicts[0].freshness, Freshness::Stale(why) if why.contains("pins none")),
            "{verdicts:?}"
        );

        // Without Cargo inputs the record is orphaned.
        fs::remove_file(dir.join("rust-toolchain.toml")).unwrap();
        fs::remove_file(dir.join("Cargo.toml")).unwrap();
        let verdicts = judge(dir, &Policy::default(), &write(body));
        assert!(
            matches!(&verdicts[0].freshness, Freshness::Stale(why) if why.contains("no cargo inputs")),
            "{verdicts:?}"
        );
    }

    #[test]
    fn closure_named_for_another_ecosystem_is_refused() {
        let temp = python_project("mismatch");
        let dir = &temp.0;
        let mut body = python_body(dir);
        body["exceptions"] = json!([]);
        // Named python.json, claims rustfmt: `sync` would refuse to read it,
        // and the gate must not judge it under either name.
        let closures = [write_closure(
            dir,
            "python",
            "rustfmt",
            Some(host().triple()),
            body,
        )];
        let present = inspect::detected(dir).unwrap();
        let error = evaluate(host(), dir, &Policy::default(), &closures, &present).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("claims ecosystem 'rustfmt' but is named 'python'"),
            "{error}"
        );
    }

    #[test]
    fn malformed_exception_record_is_an_error() {
        let temp = python_project("malformed");
        let dir = &temp.0;
        let mut body = python_body(dir);
        body["exceptions"] = json!([{"kind": "x"}]);
        let closures = [write_closure(
            dir,
            "python",
            "python",
            Some(host().triple()),
            body,
        )];
        let present = inspect::detected(dir).unwrap();
        let error = evaluate(host(), dir, &Policy::default(), &closures, &present).unwrap_err();
        assert!(
            error.to_string().contains("malformed exception record"),
            "{error}"
        );
    }

    #[test]
    fn audit_reads_the_project_without_a_store() {
        let temp = python_project("audit");
        let dir = &temp.0;
        with_exceptions(dir, &[exception(GIT_DEPENDENCY, "left-pad")]);
        let extra = deny(&[GIT_DEPENDENCY]);
        // The chain part of the policy is whatever this machine has (see
        // `effective_policy_unions...`); the extra file is under test here.
        let _env = policy::test_env_lock();
        let flag = dir.join("company.toml");
        let report = audit(host(), dir, Some((flag.as_path(), &extra))).unwrap();
        assert_eq!(report.verdicts.len(), 1);
        assert_eq!(report.verdicts[0].denied.len(), 1);
        assert!(!report.passes());
        assert!(!dir.join("store").exists());
        // Nothing synced: a NotFound with a next step.
        let empty = TempDir::new("empty");
        let error = audit(host(), &empty.0, None).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        assert!(error.to_string().contains("run 'blanket sync' first"));
    }

    #[test]
    fn company_policy_template_parses_and_names_only_known_kinds() {
        let text = include_str!("../../docs/human/policy-company.toml");
        let template = policy::parse_file(Path::new("docs/human/policy-company.toml"), text)
            .expect("the shipped template must parse against policy::KINDS");
        assert!(!template.strict, "the template must not set strict");
        let expected: BTreeSet<String> = [
            INSTALL_SCRIPT_FAILED,
            WEAK_INTEGRITY,
            policy::UNATTESTED_MUTABLE_STATE,
            policy::UNATTESTED_INDEX,
            GIT_DEPENDENCY,
            policy::LOCK_DISAGREEMENT,
            policy::ARTIFACT_NOT_PROVISIONED,
        ]
        .iter()
        .map(|kind| kind.to_string())
        .collect();
        assert_eq!(template.deny, expected);
        // Every kind the template deliberately leaves permitted is named in
        // its comments, so the file cannot silently fall behind KINDS.
        for kind in policy::KINDS {
            assert!(text.contains(kind), "template does not mention {kind}");
        }
    }
}

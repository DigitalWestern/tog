//! Running the store Ruby's Bundler as a resolver: confined through the
//! door, reaching rubygems.org only through the proxy session's RubyGems
//! mirror, or with no route at all for the helper's lock checks.

use super::{forced_env, registry, ENV_REMOVE, ENV_REMOVE_PREFIXES, GEMFILE};
use crate::kernel::resolve::door::{ConfinedSpec, Publish, ReceiptProducer, Wire, Wiring};
use crate::kernel::resolve::snapshot::PathGlob;
use crate::kernel::resolve::{DelegateReport, DelegateSpec, ResolutionDoor};
use crate::kernel::toolchain::Selected;
use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};

/// Why Bundler runs isolated, for the missing-capability message.
const WHY: &str = "evaluates the project's Gemfile and fetches the gem index from the network";

/// The files a Ruby door may publish: what `bundle lock` and `bundle add`
/// write.
pub(crate) const OUTPUTS: [&str; 2] = ["Gemfile", "Gemfile.lock"];

/// Installed gems and Bundler's own state in the project: never copied
/// into the snapshot, never diffed. A lock-only Bundler reads neither
/// (`BUNDLE_IGNORE_CONFIG=1`, gems in the run's scratch).
const EXCLUDE: [&str; 2] = ["vendor/bundle", ".bundle"];

/// Stands for the run's scratch directory in an argument: the helper and
/// any file the run is handed are written there, the one tog-written
/// directory the sandbox sees.
pub(crate) const SCRATCH: &str = "@SCRATCH@";

/// Where a confined Bundler run's results go.
pub(crate) enum RubyPublish<'a> {
    /// A planner check: nothing in the project may change. The run's
    /// ledger is kept on the door for the closure's references.
    Detached,
    /// The Gemfile and Gemfile.lock published through the transaction,
    /// with the receipt the producer makes.
    Project {
        receipt: Option<ReceiptProducer<'a>>,
    },
}

/// One confined run of the store Ruby.
pub(crate) struct RubyRun<'a> {
    pub ruby_obj: &'a Path,
    pub lock_root: &'a Path,
    /// `args[0]` is the program in the store Ruby's `bin` (`bundle`,
    /// `ruby`). [`SCRATCH`] in an argument is the run's scratch directory.
    pub args: &'a [&'a str],
    /// Reach rubygems.org through the mirror. `false` is a run with no
    /// route at all: full network denial, for the helper's lock checks.
    pub online: bool,
    /// `BUNDLE_FROZEN`: false for an edit, which must write the lock.
    pub frozen: bool,
    /// Files written into the scratch directory before the run, relative
    /// to it.
    pub files: Vec<(PathBuf, Vec<u8>)>,
    pub publish: RubyPublish<'a>,
}

/// The ruby a resolution record names: the selected release, whose
/// bundled Bundler resolved.
pub(crate) fn ruby_tool(selected: &Selected) -> io::Result<crate::kernel::resolve::record::Tool> {
    Ok(crate::kernel::resolve::record::Tool {
        name: "ruby".to_string(),
        version: selected.version("ruby")?.to_string(),
    })
}

/// The store Ruby tool `args[0]` with tog's forced environment: the store
/// Ruby alone on `PATH` beside the system directories, its output
/// captured. The gem paths are the run's scratch, set by the wiring.
fn spec(run: &RubyRun<'_>) -> DelegateSpec {
    let mut spec = DelegateSpec::new(run.ruby_obj.join("bin").join(run.args[0]));
    spec.args(&run.args[1..]).lock_root(run.lock_root);
    spec.env(
        "PATH",
        format!("{}:/usr/bin:/bin", run.ruby_obj.join("bin").display()),
    );
    let mut set = forced_env(GEMFILE, run.lock_root);
    if let Some((_, value)) = set.iter_mut().find(|(key, _)| key == "BUNDLE_FROZEN") {
        *value = run.frozen.to_string();
    }
    spec.force_env(ENV_REMOVE_PREFIXES, ENV_REMOVE, &set);
    spec.capture();
    spec
}

/// `arg` with [`SCRATCH`] replaced by `scratch`.
fn in_scratch(arg: &OsString, scratch: &Path) -> OsString {
    match arg.to_str() {
        Some(text) if text.contains(SCRATCH) => {
            text.replace(SCRATCH, &scratch.display().to_string()).into()
        }
        _ => arg.clone(),
    }
}

/// The `ConfinedSpec` of `run`: the RubyGems route when online, no route
/// otherwise.
pub(crate) fn ruby_confined<'a>(run: &mut RubyRun<'a>) -> io::Result<ConfinedSpec<'a>> {
    let mut confined = ConfinedSpec::new("ruby", "bundler", WHY);
    confined.name = "bundler";
    confined.store_reads = vec![run.ruby_obj.to_path_buf()];
    confined.exclude = EXCLUDE
        .iter()
        .map(|pattern| PathGlob::new(pattern))
        .collect::<io::Result<_>>()?;
    confined.routes = if run.online {
        vec![registry::route()?]
    } else {
        Vec::new()
    };
    let online = run.online;
    let files = std::mem::take(&mut run.files);
    confined.wire = Some(Box::new(move |wire: &Wire<'_>| {
        let gems = wire.scratch.join("gems");
        let mut env: Vec<(OsString, OsString)> = vec![
            ("GEM_HOME".into(), gems.clone().into()),
            ("GEM_PATH".into(), gems.into()),
        ];
        // A run with no route gets no proxy at all: a connection it tried
        // would fail in the sandbox rather than reach the session as a
        // refused CONNECT.
        if online {
            env.extend(
                registry::proxy_env(wire.address)
                    .into_iter()
                    .map(|(key, value)| (key.into(), value.into())),
            );
        }
        let args = wire
            .args
            .iter()
            .map(|arg| in_scratch(arg, wire.scratch))
            .chain(wire.forced_args.iter().cloned())
            .collect();
        Ok(Wiring {
            args,
            env,
            files,
            ..Wiring::default()
        })
    }));
    let publish = std::mem::replace(&mut run.publish, RubyPublish::Detached);
    confined.publish(match publish {
        RubyPublish::Detached => Publish::Detached {
            outputs: Vec::new(),
        },
        RubyPublish::Project { receipt } => Publish::Project {
            outputs: OUTPUTS.iter().map(PathBuf::from).collect(),
            receipt,
        },
    });
    Ok(confined)
}

/// Run the store Ruby confined through `door`. A Detached run's ledger is
/// kept on the door, for the closure the sync writes to refer to.
pub(crate) fn run_ruby(
    door: &mut ResolutionDoor<'_>,
    mut run: RubyRun<'_>,
) -> io::Result<DelegateReport> {
    let detached = matches!(run.publish, RubyPublish::Detached);
    let spec = spec(&run);
    let confined = ruby_confined(&mut run)?;
    let report = door.run_confined(spec, confined).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("store {}: {e}", run.args.join(" ").replace(SCRATCH, "")),
        )
    })?;
    if let (true, Some(objects)) = (detached, &report.ledger) {
        door.keep_ledger(objects.clone());
    }
    Ok(report)
}

/// `run_ruby` that fails on a nonzero exit, naming the tool's own words.
pub(crate) fn run_ruby_checked(
    door: &mut ResolutionDoor<'_>,
    run: RubyRun<'_>,
) -> io::Result<DelegateReport> {
    let what = run.args.join(" ");
    crate::kernel::ui::trace(&format!("run: {what} (in {})", run.lock_root.display()));
    let report = run_ruby(door, run)?;
    if crate::kernel::ui::verbose() {
        eprint!("{}", String::from_utf8_lossy(&report.stdout));
    }
    if !report.status.success() {
        return Err(super::err(format!(
            "store {what} failed: {}",
            String::from_utf8_lossy(&report.stderr).trim()
        )));
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_scratch_placeholder_becomes_the_runs_scratch() {
        let scratch = Path::new("/store/tmp/run");
        assert_eq!(
            in_scratch(&"@SCRATCH@/helper.rb".into(), scratch),
            OsString::from("/store/tmp/run/helper.rb")
        );
        assert_eq!(
            in_scratch(&"Gemfile".into(), scratch),
            OsString::from("Gemfile")
        );
    }

    #[test]
    fn a_run_names_the_store_ruby_alone_on_path_and_the_frozen_setting() {
        let run = RubyRun {
            ruby_obj: Path::new("/store/obj/ruby"),
            lock_root: Path::new("/work/project"),
            args: &["bundle", "lock"],
            online: true,
            frozen: false,
            files: Vec::new(),
            publish: RubyPublish::Detached,
        };
        let command = format!("{:?}", spec(&run).command());
        assert!(
            command.contains("PATH=\"/store/obj/ruby/bin:/usr/bin:/bin\""),
            "{command}"
        );
        assert!(command.contains("BUNDLE_FROZEN=\"false\""), "{command}");
        assert!(command.contains("BUNDLE_IGNORE_CONFIG=\"1\""), "{command}");
    }
}

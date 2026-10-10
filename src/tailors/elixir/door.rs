//! Running the store mix as a resolver: confined through the door,
//! reaching repo.hex.pm only through the proxy session's Hex mirror, or
//! with no route at all for the helper's lock parse.

use super::{beam_path, forced_env, registry, ENV_REMOVE, ENV_REMOVE_PREFIXES};
use crate::kernel::resolve::door::{ConfinedSpec, Publish, ReceiptProducer, Wire, Wiring};
use crate::kernel::resolve::snapshot::PathGlob;
use crate::kernel::resolve::{DelegateReport, DelegateSpec, ResolutionDoor};
use crate::kernel::toolchain::Selected;
use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};

/// Why mix runs isolated, for the missing-capability message.
const WHY: &str = "evaluates the project's mix.exs and fetches packages from the network";

/// The files an Elixir door may publish: mix.lock, beside the mix.exs the
/// record vouches for with it.
pub(crate) const OUTPUTS: [&str; 2] = ["mix.exs", "mix.lock"];

/// Fetched dependency sources and build output in the project: never
/// copied into the snapshot, never diffed. A confined mix fetches into the
/// run's scratch (`MIX_DEPS_PATH`) and builds nothing.
pub(super) const EXCLUDE: [&str; 4] = ["deps", "_build", ".git", ".tog"];

/// Stands for the run's scratch directory in an argument: the helper and
/// any file the run is handed are written there.
pub(crate) const SCRATCH: &str = "@SCRATCH@";

/// Where a confined mix run's results go.
pub(crate) enum MixPublish<'a> {
    /// A planner check: nothing in the project may change. The run's
    /// ledger is kept on the door for the closure's references.
    Detached,
    /// mix.lock published through the transaction, with the receipt the
    /// producer makes.
    Project {
        receipt: Option<ReceiptProducer<'a>>,
    },
}

/// One confined run of the store mix or elixir.
pub(crate) struct MixRun<'a> {
    pub beam_obj: &'a Path,
    pub lock_root: &'a Path,
    /// `args[0]` is `mix` or `elixir` in the store Elixir's `bin`.
    /// [`SCRATCH`] in an argument is the run's scratch directory.
    pub args: &'a [&'a str],
    /// Reach repo.hex.pm through the mirror. `false` is a run with no route
    /// at all and `HEX_OFFLINE=1`.
    pub online: bool,
    /// The exact input generation this planner consumed, if any.
    pub inputs: Option<&'a crate::comforter::join::Digests>,
    /// Files written into the scratch directory before the run, relative
    /// to it.
    pub files: Vec<(PathBuf, Vec<u8>)>,
    pub publish: MixPublish<'a>,
}

/// The tool a resolution record names: the selected Elixir, whose mix
/// resolved.
pub(crate) fn elixir_tool(selected: &Selected) -> io::Result<crate::kernel::resolve::record::Tool> {
    Ok(crate::kernel::resolve::record::Tool {
        name: "mix".to_string(),
        version: selected.version("elixir")?.to_string(),
    })
}

/// The store tool `args[0]` with tog's forced environment, its output
/// captured. The homes and the deps path are the run's scratch, set by the
/// wiring.
fn spec(run: &MixRun<'_>) -> DelegateSpec {
    let mut spec = DelegateSpec::new(run.beam_obj.join("elixir/bin").join(run.args[0]));
    spec.args(&run.args[1..]).lock_root(run.lock_root);
    spec.env("PATH", beam_path(run.beam_obj));
    // The scratch paths are placeholders here: the wiring sets each one
    // under the run's scratch directory.
    let mut set = forced_env(run.beam_obj, Path::new(SCRATCH), Path::new(SCRATCH));
    set.retain(|(key, _)| !SCRATCH_SET.contains(&key.as_str()));
    if run.online {
        set.retain(|(key, _)| key != "HEX_OFFLINE");
    }
    spec.force_env(ENV_REMOVE_PREFIXES, ENV_REMOVE, &set);
    spec.capture();
    spec
}

/// The variables the wiring sets under the run's scratch.
const SCRATCH_SET: [&str; 3] = ["MIX_DEPS_PATH", "MIX_HOME", "HEX_HOME"];

/// `arg` with [`SCRATCH`] replaced by `scratch`.
fn in_scratch(arg: &OsString, scratch: &Path) -> OsString {
    match arg.to_str() {
        Some(text) if text.contains(SCRATCH) => {
            text.replace(SCRATCH, &scratch.display().to_string()).into()
        }
        _ => arg.clone(),
    }
}

/// The `ConfinedSpec` of `run`: the Hex route when online, no route
/// otherwise.
fn mix_confined<'a>(run: &mut MixRun<'a>) -> io::Result<ConfinedSpec<'a>> {
    let mut confined = ConfinedSpec::new("elixir", "mix", WHY);
    confined.expected_inputs = run.inputs.cloned().unwrap_or_default();
    confined.complete_inputs = true;
    confined.store_reads = vec![run.beam_obj.to_path_buf()];
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
        let at = |sub: &str| OsString::from(wire.scratch.join(sub));
        let mut env: Vec<(OsString, OsString)> = vec![
            ("MIX_DEPS_PATH".into(), at("deps")),
            ("MIX_HOME".into(), at("mix")),
            ("HEX_HOME".into(), at("hex")),
        ];
        // A run with no route gets no proxy at all: Hex is offline.
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
    let publish = std::mem::replace(&mut run.publish, MixPublish::Detached);
    confined.publish(match publish {
        MixPublish::Detached => Publish::Detached {
            outputs: Vec::new(),
        },
        MixPublish::Project { receipt } => Publish::Project {
            outputs: OUTPUTS.iter().map(PathBuf::from).collect(),
            receipt,
        },
    });
    Ok(confined)
}

/// Run the store mix confined through `door`. A Detached run's ledger is
/// kept on the door, for the closure the sync writes to refer to.
pub(crate) fn run_mix(
    door: &mut ResolutionDoor<'_>,
    mut run: MixRun<'_>,
) -> io::Result<DelegateReport> {
    let detached = matches!(run.publish, MixPublish::Detached);
    let held = crate::kernel::fsroot::ProjectRoot::held_at(run.lock_root)?
        .map(Ok)
        .unwrap_or_else(|| crate::kernel::fsroot::ProjectRoot::open(run.lock_root))?;
    let captured = run
        .inputs
        .cloned()
        .map(Ok)
        .unwrap_or_else(|| super::resolve::resolution_basis(&held))?;
    let spec = spec(&run);
    let mut confined = mix_confined(&mut run)?;
    confined.expected_inputs = captured;
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

/// `run_mix` that fails on a nonzero exit, naming the tool's own words.
pub(crate) fn run_mix_checked(
    door: &mut ResolutionDoor<'_>,
    run: MixRun<'_>,
) -> io::Result<DelegateReport> {
    let what = run.args.join(" ");
    crate::kernel::ui::trace(&format!("run: {what} (in {})", run.lock_root.display()));
    let report = run_mix(door, run)?;
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

    fn run(online: bool) -> MixRun<'static> {
        MixRun {
            beam_obj: Path::new("/store/obj/beam"),
            lock_root: Path::new("/work/project"),
            args: &["mix", "deps.get"],
            online,
            inputs: None,
            files: Vec::new(),
            publish: MixPublish::Detached,
        }
    }

    /// Online, Hex is not offline and its home is the scratch's (set by
    /// the wiring); offline, `HEX_OFFLINE=1`.
    #[test]
    fn the_spec_sets_offline_only_without_a_route() {
        let online = format!("{:?}", spec(&run(true)).command());
        assert!(!online.contains("HEX_OFFLINE"), "{online}");
        assert!(!online.contains("HEX_HOME"), "{online}");
        assert!(!online.contains(SCRATCH), "{online}");
        assert!(
            online.contains("MIX_ARCHIVES=\"/store/obj/beam/archives\""),
            "{online}"
        );
        let offline = format!("{:?}", spec(&run(false)).command());
        assert!(offline.contains("HEX_OFFLINE=\"1\""), "{offline}");
    }

    #[test]
    fn the_scratch_placeholder_becomes_the_runs_scratch() {
        assert_eq!(
            in_scratch(&"@SCRATCH@/helper.exs".into(), Path::new("/s")),
            OsString::from("/s/helper.exs")
        );
    }
}

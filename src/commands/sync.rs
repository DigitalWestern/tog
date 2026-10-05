//! The bare `tog` (hidden alias `sync`): preflight every detected
//! ecosystem, then plan, realize, and project each one through the tailor
//! registry.

use crate::comforter::toolchain::{self as project_toolchain, Mode, ProjectToolchain};
use crate::commands::shared::{ecosystem_inputs, no_inputs, project_root};
use crate::kernel::context::{self, Context};
use crate::kernel::fsroot::ProjectRoot;
use crate::kernel::platform::Platform;
use crate::kernel::policy;
use crate::kernel::resolve;
use crate::kernel::resolve::{DoorKind, ResolutionDoor};
use crate::kernel::store;
use crate::tailors::{self, SyncRequest, Tailor};
use std::io;
use std::path::{Path, PathBuf};

/// Which detected tailors a sync is about: every one (the bare `tog`,
/// `add`, `update`) or the one named (the build's sync, which realizes the
/// ecosystem it builds and nothing else).
///
/// The scope decides host preflight and realization. It never narrows the
/// input check or the toolchain lock: every detected ecosystem's inputs
/// must be well-formed and resolution always covers all of them, so the
/// lock `commit` publishes is never truncated or minted from a malformed
/// request, and a stale section anywhere in the project still refuses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope<'a> {
    All,
    Only(&'a str),
}

impl Scope<'_> {
    fn covers(self, tailor: &dyn Tailor) -> bool {
        match self {
            Scope::All => true,
            Scope::Only(id) => tailor.id() == id,
        }
    }
}

/// Check the project can sync, touching no store. Returns every detected
/// tailor and the toolchain each one must use; the caller narrows the
/// tailors it runs to the same `scope` it passed here.
///
/// Host preflight runs for the tailors `scope` covers only: whether this
/// host can run an ecosystem the caller is not going to realize says
/// nothing about the one it is. Inputs are checked and the toolchain lock
/// is resolved for every detected ecosystem whatever the scope (see
/// `Scope`).
///
/// Resolution happens here, before the store is opened: a stale or
/// unresolvable toolchain must refuse without creating a store tree, taking
/// a lease, or running maintenance. Nothing is written yet either; `commit`
/// publishes a created lock once the store lease is held.
///
/// `project` is the directory the whole sync reads and writes through,
/// opened once by the caller: detection, the input check, host preflight
/// and the toolchain inputs all read the directory it holds, never
/// whatever the project's path names by then.
pub fn preflight_sync(
    platform: Platform,
    project: &ProjectRoot,
    mode: Mode,
    scope: Scope<'_>,
) -> io::Result<(Vec<&'static dyn Tailor>, ProjectToolchain)> {
    // Syncing ends by registering this project as a GC root. Check that the
    // path can be recorded before realizing or projecting anything: a
    // finished sync that could not register would leave a projected
    // environment nothing protects, and the next sweep would collect it.
    store::Store::check_registrable_in(project)?;
    let present = tailors::detected_in(project)?;
    // No project is the answer before any lock is: `tog --frozen` in the
    // wrong directory must say there is no manifest here, not that
    // tog-toolchain.toml is missing.
    if present.is_empty() {
        return Err(no_inputs());
    }
    let toolchain = preflight_detected(platform, project, &present, mode, scope)?;
    Ok((present, toolchain))
}

/// `preflight_sync` past detection: the input check and lock resolution
/// for every tailor in `present`, host preflight for the ones `scope`
/// covers.
fn preflight_detected(
    platform: Platform,
    project: &ProjectRoot,
    present: &[&dyn Tailor],
    mode: Mode,
    scope: Scope<'_>,
) -> io::Result<ProjectToolchain> {
    // The declarative inputs and the lock are read through the held root
    // descriptor, so a tampered input or lock fails closed here. Only
    // detected ecosystems are consulted, so a stray symlink for an ecosystem
    // the project does not use cannot stop its sync.
    check_inputs(project, present)?;
    // Host support next: an ecosystem that cannot run here at all says so
    // in its own words, before selection reports the same project as
    // unsatisfiable in the catalog's words.
    for tailor in present.iter().filter(|tailor| scope.covers(**tailor)) {
        tailor.preflight(platform, project)?;
    }
    let inputs = ecosystem_inputs(present)?;
    project_toolchain::resolve(project, platform, inputs, mode, policy::strict())
}

/// The bare `tog` from the command line: load policy and preflight every
/// ecosystem before the store is opened. A refused request (an unpinned
/// patch, a path no root record can hold) must leave no trace: no store
/// tree created, no maintenance sweep, no lease taken.
///
/// `records` are the `--resolution-record` paths: read now, so a
/// bad path fails before anything is realized, and judged by every closure
/// write's resolution join as evidence beside the committed receipts.
pub fn run_command(
    platform: Platform,
    fresh: bool,
    frozen: bool,
    records: &[PathBuf],
) -> io::Result<()> {
    crate::comforter::join::supply_records(records)?;
    let mode = if frozen { Mode::Frozen } else { Mode::Writable };
    run_in_mode(platform, fresh, mode, false)
}

/// The one path from a command line into a sync: preflight before the store
/// is opened, prove the project directory is still the one preflight
/// checked, then publish the lock and run the tailors.
///
/// `stop_after_lock` is `tog update --toolchain --no-sync`: the lock is the
/// deliverable, and the diff is meant to be read before anything is
/// realized from it.
pub(crate) fn run_in_mode(
    platform: Platform,
    fresh: bool,
    mode: Mode,
    stop_after_lock: bool,
) -> io::Result<()> {
    // The project above, as `run` and the bare `tog` find it, so a sync
    // from `src/` syncs the project, not `src/`.
    let dir = project_root(&context::project_dir())?;
    // An interrupted resolution publication is undone before anything
    // reads the project. Its originals are in the store, so opening the
    // store early leaves no trace a refusal would have avoided.
    let early = recover_resolution(platform, &dir)?;
    // The one descriptor this whole sync reads and writes the project
    // through, from preflight to the last closure.
    let project = ProjectRoot::open(&dir)?;
    let (present, mut toolchain) = preflight(platform, &project, mode.clone(), Scope::All)?;
    // Opening the store can wait on another process's lease. If the
    // directory was renamed or replaced meanwhile, the pathname no longer
    // names the project preflight checked: refuse now rather than at
    // publication, before any work is done for it.
    let ctx = match early {
        Some(ctx) => ctx,
        None => Context::open(platform)?,
    };
    project.check_still_named()?;
    if stop_after_lock {
        if present.is_empty() {
            return Err(no_inputs());
        }
        let _input_lock = project_toolchain::commit(&project, &mut toolchain, &mode)?;
        crate::kernel::ui::note(
            "--no-sync: read the tog-toolchain.toml diff, then run 'tog' to sync it",
        );
        return Ok(());
    }
    // A targeted update re-selects one section and copies the rest from
    // the committed file unchecked. It publishes that lock and then syncs
    // the way an ordinary sync would, so a section it left alone is still
    // held against its sources and a stale one refuses instead of being
    // realized.
    if matches!(mode, Mode::Update { only: Some(_) }) {
        {
            let _published = project_toolchain::commit(&project, &mut toolchain, &mode)?;
        }
        let (present, mut toolchain) =
            preflight_sync(platform, &project, Mode::Writable, Scope::All)?;
        return sync_preflighted(
            &ctx,
            &project,
            &present,
            &mut toolchain,
            fresh,
            &Mode::Writable,
        );
    }
    sync_preflighted(&ctx, &project, &present, &mut toolchain, fresh, &mode)
}

/// Undo an interrupted resolution publication for `dir`, if there is one,
/// returning the context opened to do it.
fn recover_resolution(platform: Platform, dir: &Path) -> io::Result<Option<Context>> {
    if !resolve::transaction::has_pending_journal(dir) {
        return Ok(None);
    }
    let ctx = Context::open(platform)?;
    resolve::transaction::recover_project(&ctx.store, &ctx.activity, dir)?;
    Ok(Some(ctx))
}

/// A sync of one named directory, with a context the caller
/// already opened: `add`/`remove`/`update` after their manifest edit, and
/// the sync `run` and `build` start.
pub(crate) fn run_in(ctx: &Context, dir: &Path, fresh: bool, frozen: bool) -> io::Result<()> {
    let mode = if frozen { Mode::Frozen } else { Mode::Writable };
    if resolve::transaction::has_pending_journal(dir) {
        resolve::transaction::recover_project(&ctx.store, &ctx.activity, dir)?;
    }
    let project = ProjectRoot::open(dir)?;
    let (present, mut toolchain) = preflight(ctx.platform, &project, mode.clone(), Scope::All)?;
    sync_preflighted(ctx, &project, &present, &mut toolchain, fresh, &mode)
}

/// Sync first when the environment for `cwd` is not the one its inputs
/// describe, and return the root whose projection the caller should read.
///
/// `tog run`, `tog env` and a delegated `tog fmt` script all want the
/// environment the project's inputs describe. Auto-syncing does that work
/// instead of refusing and making the user type the sync themselves.
/// The check is the one `tog status` prints: offline, reading the closure
/// records and hashing the inputs they name, and it is what decides, so
/// `status` and this never disagree about staleness. A directory with no
/// manifest is left alone and the caller's own message says what is
/// missing. A sync that would refuse (a stale toolchain lock, a denied
/// exception) refuses here in its own words, before the command runs.
///
/// One sync per command, and no second look: a state a sync does not
/// clear costs a sync per command, which is the habit this replaces, and
/// never a loop.
///
/// The root is found again after the sync rather than assumed: a Cargo
/// workspace member syncs and projects at the workspace root, so the
/// projection to read is not always the directory that was synced.
pub(crate) fn ensure_current(ctx: &Context, cwd: &Path, frozen: bool) -> io::Result<PathBuf> {
    ensure_current_for(ctx, cwd, None, frozen)
}

/// `ensure_current`, deciding on one ecosystem's row only when `only`
/// names it. `build` uses one environment, so a stale or broken ecosystem
/// it does not build (a Python docs tool in a Rust repo) does not start a
/// sync in front of it. When the built ecosystem is stale the sync that
/// runs is scoped to it (`Scope::Only`): only the built ecosystem is host
/// preflighted, prepared and realized, so an unrelated one this host
/// cannot run, or whose install fails (offline, a broken install script),
/// does not stop the build. Inputs are still checked and the toolchain
/// lock resolved for all of them, so the committed lock stays whole and an
/// unrelated ecosystem whose version request is malformed or whose lock
/// section is stale refuses as before. When the built ecosystem is already
/// synced and no sync runs, the same whole-project check runs on its own
/// (`check_whole_project`), so it never depends on the built row.
pub(crate) fn ensure_current_for(
    ctx: &Context,
    cwd: &Path,
    only: Option<&str>,
    frozen: bool,
) -> io::Result<PathBuf> {
    let dir = project_root(cwd)?;
    let rows = crate::commands::inspect::status(ctx.platform, &dir)?;
    let stale: Vec<String> = rows
        .iter()
        .filter(|row| only.is_none_or(|ecosystem| row.ecosystem == ecosystem))
        .filter(|row| !row.is_synced())
        .map(stale_reason)
        .collect();
    if !stale.is_empty() {
        crate::kernel::ui::note(&format!("syncing first: {}", stale.join("; ")));
        match only {
            Some(ecosystem) => run_in_only(ctx, &dir, frozen, ecosystem)?,
            None => run_in(ctx, &dir, false, frozen)?,
        }
    } else if only.is_some() {
        // No sync runs, but the rows above were narrowed to the built
        // ecosystem: the project as a whole must still be consistent. A
        // malformed version request or a stale lock section elsewhere
        // refuses the build exactly as the scoped sync would have.
        check_whole_project(ctx.platform, &dir)?;
    }
    Ok(dir)
}

/// The half of `preflight_detected` no scope narrows, for a command that
/// is not about to sync: every detected ecosystem's inputs are
/// well-formed and every committed lock section matches them. Read-only:
/// nothing is selected into a file, nothing is host-preflighted, and a
/// directory with nothing detected is left to the caller.
fn check_whole_project(platform: Platform, dir: &Path) -> io::Result<()> {
    let root = ProjectRoot::open(dir)?;
    let present = tailors::detected_in(&root)?;
    if present.is_empty() {
        return Ok(());
    }
    check_inputs(&root, &present)?;
    let inputs = ecosystem_inputs(&present)?;
    project_toolchain::resolve(&root, platform, inputs, Mode::ReadOnly, false).map(|_| ())
}

/// Every detected ecosystem's toolchain inputs, checked whatever the
/// command's scope.
fn check_inputs(project: &ProjectRoot, present: &[&dyn Tailor]) -> io::Result<()> {
    for tailor in present {
        tailor.check_inputs(project)?;
    }
    Ok(())
}

/// The build's sync: host preflight, prepare and realize the named tailor
/// only, but resolve the toolchain lock for the whole project, so the lock
/// `commit` publishes still names every detected ecosystem. Filtering the
/// tailors rather than the lock inputs is what keeps the lock whole:
/// resolving a subset would publish a lock with the other sections
/// truncated.
fn run_in_only(ctx: &Context, dir: &Path, frozen: bool, only: &str) -> io::Result<()> {
    let mode = if frozen { Mode::Frozen } else { Mode::Writable };
    let scope = Scope::Only(only);
    let project = ProjectRoot::open(dir)?;
    let (present, mut toolchain) = preflight(ctx.platform, &project, mode.clone(), scope)?;
    let scoped = scope_to(&present, scope);
    sync_preflighted(ctx, &project, &scoped, &mut toolchain, false, &mode)
}

/// The tailors one sync realizes: every detected one, or the named one.
/// `Scope::Only` always names a tailor the caller resolved first (the
/// ecosystem being built), so it is present here; anything else scopes to
/// nothing, and the empty slice fails closed in `sync_preflighted`
/// (`no_inputs`).
fn scope_to<'a>(present: &[&'a dyn Tailor], scope: Scope<'_>) -> Vec<&'a dyn Tailor> {
    present
        .iter()
        .filter(|tailor| scope.covers(**tailor))
        .copied()
        .collect()
}

/// Why one ecosystem is about to be synced, in the words `tog status`
/// uses: the ecosystem, its state, and the files or platform behind it.
fn stale_reason(row: &crate::commands::inspect::EcosystemStatus) -> String {
    use crate::comforter::status::State;
    let detail = match &row.state {
        State::Synced | State::NotSynced => String::new(),
        State::Changed(files) => format!(" ({})", files.join(", ")),
        State::ProjectionMissing(what) => format!(" ({what})"),
        State::ForeignPlatform(platform) => format!(" (last synced on {platform})"),
        State::Unchecked(_) => String::new(),
    };
    format!("{} {}{detail}", row.ecosystem, row.word().replace('-', " "))
}

fn preflight(
    platform: Platform,
    project: &ProjectRoot,
    mode: Mode,
    scope: Scope<'_>,
) -> io::Result<(Vec<&'static dyn Tailor>, ProjectToolchain)> {
    policy::init_in(project)?;
    // A configured signing key that cannot be loaded fails here, before the
    // store is opened or any closure is written.
    crate::comforter::init_signing()?;
    preflight_sync(platform, project, mode, scope)
}

/// Run the preflighted tailors through `project`, the descriptor preflight
/// read through. Each tailor reads and writes the project through it; its
/// path is checked to still name it before every tailor starts (its child
/// processes run in the project by path) and again by the closure writer
/// before anything is published.
pub(crate) fn sync_preflighted(
    ctx: &Context,
    project: &ProjectRoot,
    present: &[&'static dyn Tailor],
    toolchain: &mut ProjectToolchain,
    fresh: bool,
    mode: &Mode,
) -> io::Result<()> {
    // Nothing of this project is ours to lock: report the missing manifest
    // before a `.tog` directory appears for it.
    if present.is_empty() {
        return Err(no_inputs());
    }
    // The toolchain-input lock is taken after the store lease and before any
    // tailor runs, and held for the whole sync, so `update --toolchain`
    // cannot install a new lock while this sync plans from the old one.
    let _input_lock = project_toolchain::commit(project, toolchain, mode)?;
    let frozen = *mode == Mode::Frozen;
    let mut any = false;
    for tailor in present {
        project.check_still_named()?;
        let selected = toolchain.get(tailor.lock_ecosystem())?;
        let mut attribution = policy::Attribution::open(tailor.id())?;
        // `prepare` is missing-lock generation: it runs the ecosystem's own
        // tool in the project and writes a dependency lock. Frozen promises
        // not to modify project inputs, so it never reaches that call at
        // all; a project with no dependency lock fails inside the tailor,
        // which is the one place that knows which file is missing.
        if !frozen {
            let mut door = ResolutionDoor::open(
                &ctx.store,
                &ctx.activity,
                ctx.platform,
                DoorKind::MissingLock,
                &mut attribution,
            )?;
            tailor.prepare(ctx, project, selected, &mut door)?;
        }
        let request = SyncRequest {
            fresh,
            toolchain: selected,
            selections: &toolchain.entries,
        };
        let changed = tailor.sync(ctx, project, &request, &mut attribution)?;
        attribution.finish(changed)?;
        if changed {
            any = true;
        }
    }
    if !any {
        return Err(no_inputs());
    }
    print_exception_summary(project)?;
    print_habits_notice(&ctx.store);
    print_signing_notice(&ctx.store);
    Ok(())
}

fn print_habits_notice(store: &store::Store) {
    if let Some(message) = habits_notice(|| first_habits_notice(store)) {
        crate::kernel::ui::note(message);
    }
}

/// How a read-only environment is used, said once per store.
///
/// A pip or npm user arrives with habits this projection cannot serve:
/// there is nothing to activate and nothing to install into. `tog run`
/// refuses those commands by name when they are typed, but the first sync
/// is the moment to say which verbs replace them, before anything is typed.
fn habits_notice(first_for_this_store: impl FnOnce() -> bool) -> Option<&'static str> {
    first_for_this_store().then_some(
        "this environment is read-only: there is no activate script and no pip or npm \
         install into it. Run things with 'tog run <command>' or 'tog <script>', change \
         dependencies with 'tog add <package>' and 'tog remove <package>', and give a \
         shell the environment with eval \"$(tog env)\". Said once per store",
    )
}

/// Claim the once-per-store habits notice, the way `first_signing_notice`
/// claims its own: the marker's creation is the claim, so two concurrent
/// syncs say it once between them, and a store that cannot be written stays
/// quiet rather than nagging every sync.
fn first_habits_notice(store: &store::Store) -> bool {
    claim_habits_notice(store, crate::kernel::ui::quiet())
}

/// The claim with the quiet decision passed in, so a test can exercise the
/// rule without silencing the test binary's stderr: `--quiet` drops the line
/// on the way out, and the user would have spent their one showing on a run
/// that could not display it.
fn claim_habits_notice(store: &store::Store, quiet: bool) -> bool {
    if quiet {
        return false;
    }
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(store.root.join("habits-notice"))
        .is_ok()
}

fn print_signing_notice(store: &store::Store) {
    let signed = crate::comforter::signing_key().is_some();
    let matters = policy::signing_configured();
    // Claim the once-per-store slot only when the answer could depend on
    // it, so a signed sync does not burn it.
    let first = || !signed && !matters && first_signing_notice(store);
    if let Some((message, fix)) =
        signing_notice(signed, matters, first, default_signing_key().is_file())
    {
        crate::kernel::ui::warning(message, &fix);
    }
}

/// Where the fix line tells a solo user to keep a key: next to the store's
/// default home, so the same path works on every machine they set up.
fn default_signing_key() -> PathBuf {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    home.unwrap_or_else(|| PathBuf::from("~"))
        .join(".tog")
        .join("signing.key")
}

/// What to say about unsigned closures, if anything.
///
/// Unsigned is the default and is fine for a solo project, so it is worth
/// saying once per store, not as the last line of every sync. It stays on
/// every sync only where a `[signing]` table proves someone is checking
/// signatures: there an unsigned closure is a finding, not a preference.
///
/// The fix is the whole way out, not half of it: a key has to exist and
/// `TOG_SIGNING_KEY` has to name it. `keygen` refuses to overwrite a key,
/// so when the default one is already there the fix is only the export.
/// Under a policy that names trusted keys a fresh key would not be
/// trusted, so that fix names the key file the policy trusts instead.
fn signing_notice(
    signed: bool,
    signing_in_policy: bool,
    first_for_this_store: impl FnOnce() -> bool,
    default_key_exists: bool,
) -> Option<(&'static str, String)> {
    if signed {
        return None;
    }
    if signing_in_policy {
        return Some((
            "closures written unsigned while this policy declares [signing] trusted keys: \
             'tog audit' will report them outdated until TOG_SIGNING_KEY names a key the \
             policy trusts",
            "export TOG_SIGNING_KEY=<key file this policy trusts>".to_string(),
        ));
    }
    let fix = if default_key_exists {
        format!("export TOG_SIGNING_KEY={DEFAULT_KEY}")
    } else {
        format!("tog keygen {DEFAULT_KEY} && export TOG_SIGNING_KEY={DEFAULT_KEY}")
    };
    first_for_this_store().then_some((
        "closures are written unsigned, which is fine until you want 'tog audit' to vouch \
         for them; the fix sets a key for this shell, and a shell profile keeps it. Said \
         once per store",
        fix,
    ))
}

/// How the fix line spells `default_signing_key()`: the shell expands `~`.
const DEFAULT_KEY: &str = "~/.tog/signing.key";

/// Claim the once-per-store signing notice. The marker's creation is the
/// claim (`create_new`), so two concurrent syncs print it once between
/// them; a store that cannot be written stays quiet rather than nagging.
///
/// `--quiet` never claims it: the line would be dropped on the way out and
/// the user would have spent their one showing on a run that could not
/// display it.
fn first_signing_notice(store: &store::Store) -> bool {
    if crate::kernel::ui::quiet() {
        return false;
    }
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(store.root.join("signing-notice"))
        .is_ok()
}

/// The exceptions recorded across the project's closures, read through the
/// held project with the strict no-follow walk: closures are tog's own
/// state, so a symlinked `.tog` or closure file counts nothing rather than
/// being read through. The summary is advisory, so an unreadable or
/// malformed closure is skipped.
fn exception_count(project: &ProjectRoot) -> usize {
    let dir = Path::new(".tog/closures");
    let mut total = 0;
    if let Ok(Some(names)) = project.read_dir(dir) {
        for name in names {
            if !name.to_string_lossy().ends_with(".json")
                || crate::kernel::store::is_retired_closure(Path::new(&name))
            {
                continue;
            }
            let bytes = match project.read_file(&dir.join(&name)) {
                Ok(Some(bytes)) => bytes,
                _ => continue,
            };
            let value: serde_json::Value = match serde_json::from_slice(&bytes) {
                Ok(value) => value,
                Err(_) => continue,
            };
            total += value["body"]["exceptions"].as_array().map_or(0, Vec::len);
        }
    }
    total
}

fn print_exception_summary(project: &ProjectRoot) -> io::Result<()> {
    // The audit's own refusal: CI set and no [signing] table in the chain.
    let unsigned_refused = !policy::signing_configured()
        && crate::commands::audit::ci_environment(std::env::var_os("CI").as_deref());
    if let Some((message, next)) = exception_summary(exception_count(project), unsigned_refused) {
        crate::kernel::ui::warning_next(&message, next);
    }
    Ok(())
}

/// A count and the command that judges it. The line this replaces advised
/// `tog --strict`, which does not refuse the recorded exceptions: it fails
/// the sync that recorded them, undoing the work that just finished.
///
/// `tog audit` is the `next:` line whether or not a `[signing]` table is
/// configured: without one it judges the exceptions against the policy and
/// says that signatures were not checked. Under CI with no table a plain
/// audit exits 2 instead (`unsigned_refused`), so the line adds
/// `--allow-unsigned`. `next:`, not `fix:`: the audit says whether an
/// exception matters under the policy, and the exception stays recorded
/// either way.
fn exception_summary(total: usize, unsigned_refused: bool) -> Option<(String, &'static str)> {
    (total > 0).then(|| {
        (
            format!("{total} policy exception(s) recorded in .tog/closures/*.json"),
            if unsigned_refused {
                "tog audit --allow-unsigned"
            } else {
                "tog audit"
            },
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::testutil::TempDir;
    use std::ffi::OsString;

    struct StoreEnv(Option<OsString>);

    impl StoreEnv {
        fn enter(path: &Path) -> Self {
            let old = std::env::var_os("TOG_STORE");
            std::env::set_var("TOG_STORE", path);
            Self(old)
        }
    }

    impl Drop for StoreEnv {
        fn drop(&mut self) {
            match self.0.take() {
                Some(value) => std::env::set_var("TOG_STORE", value),
                None => std::env::remove_var("TOG_STORE"),
            }
        }
    }

    /// Scrubs every variable `preflight` reads (policy chain, strictness,
    /// and the signing key) so a developer's environment cannot reach a
    /// test: an exported TOG_SIGNING_KEY would otherwise fail preflight
    /// here, or pin a real key for the rest of the test binary.
    struct PolicyEnv {
        home: Option<OsString>,
        policy: Option<OsString>,
        strict: Option<OsString>,
        signing_key: Option<OsString>,
    }

    impl PolicyEnv {
        fn enter(home: &Path) -> Self {
            let old = Self {
                home: std::env::var_os("HOME"),
                policy: std::env::var_os("TOG_POLICY"),
                strict: std::env::var_os("TOG_STRICT"),
                signing_key: std::env::var_os("TOG_SIGNING_KEY"),
            };
            std::env::set_var("HOME", home);
            std::env::remove_var("TOG_POLICY");
            std::env::remove_var("TOG_STRICT");
            std::env::remove_var("TOG_SIGNING_KEY");
            old
        }
    }

    impl Drop for PolicyEnv {
        fn drop(&mut self) {
            match self.home.take() {
                Some(value) => std::env::set_var("HOME", value),
                None => std::env::remove_var("HOME"),
            }
            match self.policy.take() {
                Some(value) => std::env::set_var("TOG_POLICY", value),
                None => std::env::remove_var("TOG_POLICY"),
            }
            match self.strict.take() {
                Some(value) => std::env::set_var("TOG_STRICT", value),
                None => std::env::remove_var("TOG_STRICT"),
            }
            match self.signing_key.take() {
                Some(value) => std::env::set_var("TOG_SIGNING_KEY", value),
                None => std::env::remove_var("TOG_SIGNING_KEY"),
            }
        }
    }

    /// A solo user's first sync should not end on an Ed25519 key-management
    /// warning, and the one after it should not repeat it. Where a policy
    /// declares trusted keys, unsigned is a finding and the line stays.
    #[test]
    fn the_signing_notice_is_once_per_store_unless_a_policy_asks_for_signatures() {
        // Signed: nothing to say, and the once-per-store slot is untouched.
        assert!(signing_notice(true, false, || panic!("slot claimed"), false).is_none());
        assert!(signing_notice(true, true, || panic!("slot claimed"), false).is_none());

        let (unsigned, fix) =
            signing_notice(false, false, || true, false).expect("the first sync says it");
        assert!(unsigned.contains("once per store"), "{unsigned}");
        assert_eq!(
            fix,
            "tog keygen ~/.tog/signing.key && export TOG_SIGNING_KEY=~/.tog/signing.key"
        );
        // A key that already exists must not be overwritten: the fix is
        // then only the export.
        let (_, fix) = signing_notice(false, false, || true, true).unwrap();
        assert_eq!(fix, "export TOG_SIGNING_KEY=~/.tog/signing.key");
        assert!(signing_notice(false, false, || false, false).is_none());

        // A [signing] table means someone reads signatures: say it every
        // time, whatever the once-per-store slot holds, and a fresh key
        // would not be one the policy trusts.
        let (policy_cares, policy_fix) =
            signing_notice(false, true, || false, true).expect("a policy wants signing");
        assert!(policy_cares.contains("[signing]"), "{policy_cares}");
        assert_eq!(
            policy_fix,
            "export TOG_SIGNING_KEY=<key file this policy trusts>"
        );

        // The slot is a real once-per-store claim, not a coin flip.
        let temp = TempDir::new();
        let store = store::Store::for_test(temp.0.clone());
        assert!(first_signing_notice(&store));
        assert!(!first_signing_notice(&store));
    }

    /// A pip or npm user's habits stop working the moment an environment is
    /// projected, so the first sync in a store names the verbs that replace
    /// them and every sync after it stays quiet.
    #[test]
    fn the_habits_note_is_said_once_per_store_and_never_under_quiet() {
        let said = habits_notice(|| true).expect("the first sync says it");
        assert!(said.contains("read-only"), "{said}");
        assert!(said.contains("no activate script"), "{said}");
        assert!(said.contains("tog run <command>"), "{said}");
        assert!(said.contains("tog add <package>"), "{said}");
        assert!(said.contains("tog env"), "{said}");
        assert!(said.contains("Said once per store"), "{said}");
        assert!(habits_notice(|| false).is_none());

        // The slot is a real once-per-store claim, not a coin flip.
        let temp = TempDir::new();
        let store = store::Store::for_test(temp.0.clone());
        assert!(claim_habits_notice(&store, false));
        assert!(!claim_habits_notice(&store, false));

        // Quiet would drop the line on the way out, so it never spends the
        // showing: a fresh store is left unclaimed for a loud run.
        let quiet_temp = TempDir::new();
        let quiet_store = store::Store::for_test(quiet_temp.0.clone());
        assert!(!claim_habits_notice(&quiet_store, true));
        assert!(!quiet_store.root.join("habits-notice").exists());
        assert!(claim_habits_notice(&quiet_store, false));

        // A store that cannot be written stays quiet rather than nagging.
        let unwritable = store::Store::for_test(temp.0.join("no/such/store"));
        assert!(!claim_habits_notice(&unwritable, false));
    }

    /// `tog --strict` does not refuse recorded exceptions; it fails
    /// the sync that recorded them. The summary must not advise it.
    #[test]
    fn the_exception_summary_counts_and_points_at_a_read_command() {
        assert_eq!(exception_summary(0, false), None);
        assert_eq!(exception_summary(0, true), None);
        let (line, next) = exception_summary(3, false).unwrap();
        assert!(line.starts_with("3 policy exception(s) recorded"), "{line}");
        assert!(line.contains(".tog/closures/*.json"), "{line}");
        // Outside CI `tog audit` runs with or without trusted keys, so the
        // count always has a command to type.
        assert_eq!(next, "tog audit");
        assert!(!line.contains("--strict"), "{line}");
        assert!(!line.contains("[signing]"), "{line}");
        // Under CI with no [signing] table a plain audit exits 2, so the
        // command to type is the one that runs.
        let (ci_line, ci_next) = exception_summary(3, true).unwrap();
        assert_eq!(ci_line, line);
        assert_eq!(ci_next, "tog audit --allow-unsigned");
    }

    /// Closures are tog's own state: sync's exception summary reads them
    /// through the held project with the strict no-follow walk, so a
    /// symlinked `.tog` or closure file counts nothing instead of being read
    /// through to another directory.
    #[test]
    fn closures_are_read_without_following_a_symlink() {
        let temp = TempDir::new();
        let project = temp.0.join("project");
        let outside = temp.0.join("outside");
        std::fs::create_dir_all(project.join(".tog/closures")).unwrap();
        std::fs::create_dir_all(outside.join("closures")).unwrap();
        let closure = serde_json::json!({
            "schema": "closure/1",
            "ecosystem": "python",
            "body": {"exceptions": [{"kind": "a"}, {"kind": "b"}]},
        })
        .to_string();
        std::fs::write(project.join(".tog/closures/python.json"), &closure).unwrap();
        std::fs::write(outside.join("closures/python.json"), &closure).unwrap();
        let root = ProjectRoot::open(&project).unwrap();
        assert_eq!(exception_count(&root), 2);

        // A symlinked closure file.
        std::fs::remove_file(project.join(".tog/closures/python.json")).unwrap();
        std::os::unix::fs::symlink(
            outside.join("closures/python.json"),
            project.join(".tog/closures/python.json"),
        )
        .unwrap();
        assert_eq!(exception_count(&root), 0);

        // A symlinked `.tog`.
        std::fs::remove_dir_all(project.join(".tog")).unwrap();
        std::os::unix::fs::symlink(&outside, project.join(".tog")).unwrap();
        assert_eq!(exception_count(&root), 0);
    }

    /// Sync ends by registering the project as a GC root, so a path no
    /// record can hold is refused before an environment is realized or
    /// projected. Refusing at the end instead would leave the project synced,
    /// unprotected and with no way to register it.
    #[test]
    fn sync_refuses_a_project_path_no_root_record_can_hold() {
        let temp = TempDir::new();
        let project = temp.0.join("project ");
        std::fs::create_dir_all(&project).unwrap();
        let Err(error) = preflight_sync(
            Platform::host().unwrap(),
            &ProjectRoot::open(&project).unwrap(),
            Mode::Writable,
            Scope::All,
        ) else {
            panic!("an unregistrable project path was accepted");
        };
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("cannot protect"), "{error}");
    }

    #[test]
    fn first_sync_preflight_selects_and_commit_writes_the_lock() {
        // Preflight selects and writes nothing; commit publishes the
        // canonical bytes; the next resolve honors the file it wrote.
        use crate::kernel::toolchain::lock::ToolchainLock;
        use crate::kernel::toolchain::{input, Source};
        // `commit` installs a process-global guard and dropping it clears
        // that guard, so this test cannot run beside one that is reading
        // it. Every closure writer holds the attribution lock.
        let _attribution = policy::attribution_test_lock();
        let temp = TempDir::new();
        let project = temp.0.join("project");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(
            project.join("pyproject.toml"),
            "[project]\nname = \"fixture\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        std::fs::write(project.join(".python-version"), "3.12.14\n").unwrap();
        let platform = Platform::host().unwrap();
        let (present, mut toolchain) = preflight_sync(
            platform,
            &ProjectRoot::open(&project).unwrap(),
            Mode::Writable,
            Scope::All,
        )
        .unwrap();
        assert!(present.iter().any(|tailor| tailor.id() == "python"));
        assert!(!project.join("tog-toolchain.toml").exists());
        let selected = toolchain.get("python").unwrap();
        assert_eq!(selected.source, Source::Created);
        assert_eq!(selected.version("cpython").unwrap(), "3.12.14");
        let chosen = selected.bundle_id();

        let root = ProjectRoot::open(&project).unwrap();
        let rows = input::discover(&root, "python").unwrap();
        assert_eq!(rows[0].value.as_deref(), Some("3.12.14"));
        let pending = toolchain.pending.as_ref().unwrap().canonical_bytes();
        let guard = project_toolchain::commit(&root, &mut toolchain, &Mode::Writable).unwrap();
        let written = std::fs::read(project.join("tog-toolchain.toml")).unwrap();
        assert_eq!(written, pending);
        assert_eq!(
            ToolchainLock::parse(&written).unwrap().canonical_bytes(),
            written
        );
        drop(guard);

        let (_, again) = preflight_sync(
            platform,
            &ProjectRoot::open(&project).unwrap(),
            Mode::Writable,
            Scope::All,
        )
        .unwrap();
        let honored = again.get("python").unwrap();
        assert_eq!(honored.source, Source::Lock);
        assert_eq!(honored.bundle_id(), chosen);
        assert!(again.pending.is_none());

        // Every tailor's lock ecosystem is one discovery knows.
        for tailor in tailors::registry() {
            assert!(
                input::ECOSYSTEMS.contains(&tailor.lock_ecosystem()),
                "{}",
                tailor.id()
            );
        }
    }

    #[test]
    fn preflight_fails_closed_on_a_symlinked_toolchain_input() {
        // The guarantee end to end: a symlinked input of a detected
        // ecosystem stops sync before the store opens.
        let temp = TempDir::new();
        let project = temp.0.join("project");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(
            project.join("pyproject.toml"),
            "[project]\nname = \"fixture\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        let victim = temp.0.join("victim");
        std::fs::write(&victim, "3.12.14\n").unwrap();
        std::os::unix::fs::symlink(&victim, project.join(".python-version")).unwrap();
        let Err(error) = preflight_sync(
            Platform::host().unwrap(),
            &ProjectRoot::open(&project).unwrap(),
            Mode::Writable,
            Scope::All,
        ) else {
            panic!("a symlinked .python-version was read through");
        };
        assert!(error.to_string().contains("is a symlink"), "{error}");
        // The same symlink for an ecosystem the project does not use is
        // not consulted.
        std::fs::remove_file(project.join(".python-version")).unwrap();
        std::fs::write(project.join(".python-version"), "3.12.14\n").unwrap();
        std::os::unix::fs::symlink(&victim, project.join(".ruby-version")).unwrap();
        preflight_sync(
            Platform::host().unwrap(),
            &ProjectRoot::open(&project).unwrap(),
            Mode::Writable,
            Scope::All,
        )
        .unwrap();
    }

    /// The reason line is the `status` vocabulary with the detail that
    /// names the file or platform behind it, so the sync a command starts
    /// on its own says why in the same words `tog status` would.
    #[test]
    fn stale_reasons_name_the_state_and_what_is_behind_it() {
        use crate::comforter::status::State;
        let row = |ecosystem: &str, state: State| crate::commands::inspect::EcosystemStatus {
            ecosystem: ecosystem.into(),
            state,
            summary: String::new(),
            exceptions: Vec::new(),
            exceptions_error: None,
        };
        assert_eq!(
            stale_reason(&row("node", State::NotSynced)),
            "node not synced"
        );
        assert_eq!(
            stale_reason(&row(
                "python",
                State::Changed(vec!["requirements.txt".into(), "pyproject.toml".into()])
            )),
            "python changed (requirements.txt, pyproject.toml)"
        );
        assert_eq!(
            stale_reason(&row(
                "node",
                State::ProjectionMissing("node_modules".into())
            )),
            "node projection missing (node_modules)"
        );
        assert_eq!(
            stale_reason(&row(
                "python",
                State::ForeignPlatform("aarch64-apple-darwin".into())
            )),
            "python foreign platform (last synced on aarch64-apple-darwin)"
        );
        assert_eq!(
            stale_reason(&row(
                "go",
                State::Unchecked("inputs were not recorded".into())
            )),
            "go unchecked"
        );
    }

    /// `ensure_current` is a no-op where there is no manifest, so the
    /// calling command's own message explains; where a manifest exists and
    /// nothing is synced, it is the sync that runs, refusals included.
    #[test]
    fn ensure_current_syncs_a_project_and_leaves_a_bare_directory_alone() {
        // Same lock order as `failed_tailor_sync_clears_its_unpublished_exceptions`.
        let _env_lock = policy::test_env_lock();
        let temp = TempDir::new();
        let home = temp.0.join("home");
        std::fs::create_dir_all(&home).unwrap();
        let _policy_env = PolicyEnv::enter(&home);
        let _store_lock = store::STORE_ENV_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let _attribution = policy::attribution_test_lock();
        let bare = temp.0.join("bare");
        std::fs::create_dir_all(&bare).unwrap();
        let project = temp.0.join("project");
        std::fs::create_dir_all(&project).unwrap();
        // A CPython no catalog has: the sync stops at selection, offline,
        // which is proof enough that it was started.
        std::fs::write(
            project.join("pyproject.toml"),
            "[project]\nname = \"fixture\"\nversion = \"0.1.0\"\nrequires-python = \"==0.0.1\"\n",
        )
        .unwrap();
        let nested = project.join("src").join("deep");
        std::fs::create_dir_all(&nested).unwrap();
        let _store_env = StoreEnv::enter(&temp.0.join("store"));
        let ctx = Context::open_in(Platform::host().unwrap(), &bare).unwrap();

        let root =
            ensure_current(&ctx, &bare, false).expect("a directory with no manifest is left alone");
        assert_eq!(root, bare);
        assert!(!bare.join(".tog").exists());

        let error = ensure_current(&ctx, &project, false).unwrap_err();
        assert!(error.to_string().contains("no pinned CPython"), "{error}");
        // From a subdirectory the manifest above is the project.
        let error = ensure_current(&ctx, &nested, false).unwrap_err();
        assert!(error.to_string().contains("no pinned CPython"), "{error}");
        assert_eq!(project_root(&nested).unwrap(), project);
        assert_eq!(project_root(&bare).unwrap(), bare);
    }

    /// The build's sync realizes the built ecosystem only: with two
    /// ecosystems detected, scoping to one leaves the other out. The lock
    /// stays whole regardless, because `commit` publishes the full pending
    /// toolchain whatever slice the tailor loop is given.
    #[test]
    fn build_sync_scopes_to_the_built_ecosystem() {
        let present = tailors::registry();
        assert!(present.len() > 1, "needs two ecosystems to scope");
        assert_eq!(scope_to(present, Scope::All).len(), present.len());
        let scoped = scope_to(present, Scope::Only("cargo"));
        assert_eq!(scoped.len(), 1);
        assert_eq!(scoped[0].id(), "cargo");
        assert!(scoped.iter().all(|tailor| tailor.id() != "python"));
        // An unknown name scopes to nothing, which fails closed downstream
        // (`sync_preflighted` refuses an empty slice).
        assert!(scope_to(present, Scope::Only("cobol")).is_empty());
    }

    /// The Python tailor on a host it cannot run on: every method is the
    /// real one except host preflight, which refuses. The shipped pin
    /// tables cover the same CPythons on every platform, so no real input
    /// produces a host-only refusal on the test's own host.
    struct HostlessPython;

    impl HostlessPython {
        fn real() -> &'static dyn Tailor {
            tailors::by_id("python").unwrap()
        }
    }

    impl Tailor for HostlessPython {
        fn input_files(&self) -> &'static str {
            "test input"
        }
        fn id(&self) -> &'static str {
            "python"
        }
        fn detect(&self, project: &ProjectRoot) -> io::Result<bool> {
            Self::real().detect(project)
        }
        fn check_inputs(&self, project: &ProjectRoot) -> io::Result<()> {
            Self::real().check_inputs(project)
        }
        fn preflight(&self, _platform: Platform, _project: &ProjectRoot) -> io::Result<()> {
            Err(io::Error::other("CPython: no build for this host"))
        }
        fn plan(
            &self,
            ctx: &Context,
            project: &ProjectRoot,
            toolchain: &crate::kernel::toolchain::Selected,
            door: &mut ResolutionDoor<'_>,
        ) -> io::Result<Option<String>> {
            Self::real().plan(ctx, project, toolchain, door)
        }
        fn sync(
            &self,
            ctx: &Context,
            project: &ProjectRoot,
            request: &SyncRequest,
            attribution: &mut policy::Attribution,
        ) -> io::Result<bool> {
            Self::real().sync(ctx, project, request, attribution)
        }
        fn listing(&self, ecosystem: &str, body: &serde_json::Value) -> tailors::ClosureListing {
            Self::real().listing(ecosystem, body)
        }
        fn closure_state(
            &self,
            platform: Platform,
            project: &ProjectRoot,
            ecosystem: &str,
            body: &serde_json::Value,
        ) -> io::Result<crate::comforter::status::State> {
            Self::real().closure_state(platform, project, ecosystem, body)
        }
        fn sbom_components(
            &self,
            ecosystem: &str,
            body: &serde_json::Value,
            out: &mut Vec<serde_json::Value>,
        ) -> io::Result<()> {
            Self::real().sbom_components(ecosystem, body, out)
        }
        fn toolchain_catalog(&self) -> io::Result<crate::kernel::toolchain::Catalog> {
            Self::real().toolchain_catalog()
        }
    }

    /// A build whose own ecosystem is synced runs no sync, so the
    /// whole-project half of preflight runs on its own: a stale Python
    /// lock section or a malformed Python request refuses, read-only.
    #[test]
    fn a_synced_build_still_checks_the_whole_project() {
        // `commit` installs a process-global guard; same locks as
        // `first_sync_preflight_selects_and_commit_writes_the_lock`.
        let _attribution = policy::attribution_test_lock();
        let temp = TempDir::new();
        let project = temp.0.join("project");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(
            project.join("Cargo.toml"),
            "[package]\nname = \"p\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        let pyproject = "[project]\nname = \"fixture\"\nversion = \"0.1.0\"\n";
        std::fs::write(project.join("pyproject.toml"), pyproject).unwrap();
        std::fs::write(project.join(".python-version"), "3.12\n").unwrap();
        let platform = Platform::host().unwrap();
        let (_, mut toolchain) = preflight_sync(
            platform,
            &ProjectRoot::open(&project).unwrap(),
            Mode::Writable,
            Scope::All,
        )
        .unwrap();
        let root = ProjectRoot::open(&project).unwrap();
        drop(project_toolchain::commit(&root, &mut toolchain, &Mode::Writable).unwrap());
        let lock = std::fs::read(project.join("tog-toolchain.toml")).unwrap();
        check_whole_project(platform, &project).unwrap();

        std::fs::write(project.join(".python-version"), "3.13\n").unwrap();
        let error = check_whole_project(platform, &project).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("tog-toolchain.toml is stale for python"),
            "{error}"
        );

        std::fs::write(project.join(".python-version"), "3.12\n").unwrap();
        std::fs::write(
            project.join("pyproject.toml"),
            format!("{pyproject}requires-python = \"invalid\"\n"),
        )
        .unwrap();
        let error = check_whole_project(platform, &project).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("invalid PEP 440 specifier `invalid`"),
            "{error}"
        );
        assert_eq!(
            std::fs::read(project.join("tog-toolchain.toml")).unwrap(),
            lock
        );
    }

    /// Host preflight follows the scope (#159); the input check and lock
    /// resolution do not. A Cargo build beside a Python project this host
    /// cannot run resolves both lock sections, while every other sync still
    /// refuses on the host, and a malformed Python request refuses whatever
    /// the scope.
    #[test]
    fn host_preflight_follows_the_scope_and_the_input_check_does_not() {
        let temp = TempDir::new();
        let project = temp.0.join("project");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(
            project.join("Cargo.toml"),
            "[package]\nname = \"p\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        std::fs::write(
            project.join("pyproject.toml"),
            "[project]\nname = \"fixture\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        let platform = Platform::host().unwrap();
        let present: [&dyn Tailor; 2] = [&HostlessPython, tailors::by_id("cargo").unwrap()];

        let error = preflight_detected(
            platform,
            &ProjectRoot::open(&project).unwrap(),
            &present,
            Mode::Writable,
            Scope::All,
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("no build for this host"),
            "{error}"
        );

        let toolchain = preflight_detected(
            platform,
            &ProjectRoot::open(&project).unwrap(),
            &present,
            Mode::Writable,
            Scope::Only("cargo"),
        )
        .unwrap();
        toolchain.get("python").unwrap();
        toolchain.get("rust").unwrap();

        std::fs::write(
            project.join("pyproject.toml"),
            "[project]\nname = \"fixture\"\nversion = \"0.1.0\"\nrequires-python = 3\n",
        )
        .unwrap();
        let error = preflight_detected(
            platform,
            &ProjectRoot::open(&project).unwrap(),
            &present,
            Mode::Writable,
            Scope::Only("cargo"),
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("requires-python must be a string"),
            "{error}"
        );
    }

    #[test]
    fn failed_tailor_sync_clears_its_unpublished_exceptions() {
        // Process-global test state follows env -> store -> attribution.
        // Every multi-guard holder takes them in this order: commands::deps
        // (store -> attribution), commands::inspect's doctor tests (env ->
        // store). One shared total order, so no holder can wait on a lock
        // another holder has taken after an earlier one.
        let _env_lock = policy::test_env_lock();
        let temp = TempDir::new();
        let home = temp.0.join("home");
        std::fs::create_dir_all(&home).unwrap();
        let _policy_env = PolicyEnv::enter(&home);
        let _store_lock = store::STORE_ENV_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let _attribution = policy::attribution_test_lock();
        let project = temp.0.join("project");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(
            project.join("pyproject.toml"),
            "[project]\nname = \"fixture\"\nversion = \"0.1.0\"\n\n[project.optional-dependencies]\na = [\"optional-package\"]\nz = \"malformed group\"\n",
        )
        .unwrap();
        let _store_env = StoreEnv::enter(&temp.0.join("store"));
        let ctx = Context::open_in(Platform::host().unwrap(), &project).unwrap();

        let error = run_in(&ctx, &project, false, false).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("optional-dependencies values must be arrays"),
            "{error}"
        );
        assert!(
            policy::pending().is_empty(),
            "failed tailor left an exception queued: {:?}",
            policy::pending()
        );
        let next = policy::Attribution::open("node").unwrap();
        drop(next);
    }

    /// The Python tailor whose `sync` has a same-user process rename the
    /// project away and put another project at its path mid-sync, then
    /// publishes the way every producer does: the production closure writer,
    /// through the held root, with a complete object reference, so the only
    /// thing that can stop the publication is a still-named check.
    struct SwappedMidSync {
        moved: PathBuf,
    }

    /// A complete store object for a closure to reference, made under the
    /// command's own lease.
    fn complete_object(ctx: &Context, name: &str) -> io::Result<String> {
        use std::os::unix::fs::PermissionsExt as _;
        crate::kernel::objmeta::register_test_kinds();
        let identity = crate::kernel::types::Identity {
            kind: "test".into(),
            name: name.into(),
            version: "1".into(),
            inputs: Default::default(),
        };
        let id = identity.object_id();
        let staged = ctx.store.stage_with_activity(&ctx.activity)?;
        std::fs::write(staged.join("payload"), name)?;
        ctx.store.commit_with_activity_and_deps(
            &ctx.activity,
            &identity,
            &staged,
            &[],
            &crate::kernel::store::ObjectDeps::new(),
        )?;
        let object = ctx.store.object_path(&id);
        let mut perms = std::fs::metadata(&object)?.permissions();
        perms.set_mode(perms.mode() & !0o222);
        std::fs::set_permissions(&object, perms)?;
        Ok(id)
    }

    impl Tailor for SwappedMidSync {
        fn input_files(&self) -> &'static str {
            "test input"
        }
        fn id(&self) -> &'static str {
            "python"
        }
        fn detect(&self, project: &ProjectRoot) -> io::Result<bool> {
            HostlessPython::real().detect(project)
        }
        fn preflight(&self, _platform: Platform, _project: &ProjectRoot) -> io::Result<()> {
            Ok(())
        }
        fn plan(
            &self,
            _ctx: &Context,
            _project: &ProjectRoot,
            _toolchain: &crate::kernel::toolchain::Selected,
            _door: &mut ResolutionDoor<'_>,
        ) -> io::Result<Option<String>> {
            Ok(None)
        }
        fn sync(
            &self,
            ctx: &Context,
            project: &ProjectRoot,
            _request: &SyncRequest,
            attribution: &mut policy::Attribution,
        ) -> io::Result<bool> {
            let manifest = Path::new("pyproject.toml");
            let before = project.read_input(manifest)?.unwrap();
            let id = complete_object(ctx, "swapped-mid-sync")?;
            let mut refs = crate::comforter::ClosureRefs::new();
            refs.object_id(&ctx.store, &ctx.activity, &id)?;
            let path = project.path().to_path_buf();
            std::fs::rename(&path, &self.moved)?;
            std::fs::create_dir_all(&path)?;
            std::fs::write(
                path.join("pyproject.toml"),
                "[project]\nname = \"impostor\"\nversion = \"6.6.6\"\n",
            )?;
            std::fs::write(path.join(".python-version"), "3.12.14\n")?;
            // The held descriptor still reads the project preflight checked.
            assert_eq!(project.read_input(manifest)?.unwrap(), before);
            crate::comforter::write_closure(
                project,
                "python",
                serde_json::json!({}),
                &ctx.store,
                &ctx.activity,
                refs,
                attribution,
            )?;
            Ok(true)
        }
        fn listing(&self, ecosystem: &str, body: &serde_json::Value) -> tailors::ClosureListing {
            HostlessPython::real().listing(ecosystem, body)
        }
        fn closure_state(
            &self,
            platform: Platform,
            project: &ProjectRoot,
            ecosystem: &str,
            body: &serde_json::Value,
        ) -> io::Result<crate::comforter::status::State> {
            HostlessPython::real().closure_state(platform, project, ecosystem, body)
        }
        fn sbom_components(
            &self,
            ecosystem: &str,
            body: &serde_json::Value,
            out: &mut Vec<serde_json::Value>,
        ) -> io::Result<()> {
            HostlessPython::real().sbom_components(ecosystem, body, out)
        }
        fn toolchain_catalog(&self) -> io::Result<crate::kernel::toolchain::Catalog> {
            HostlessPython::real().toolchain_catalog()
        }
    }

    /// #55: a project directory renamed away and replaced by another project
    /// at the same path mid-sync is refused before anything is published, in
    /// either directory. The tailor kept reading the original through the
    /// held descriptor the whole time.
    #[test]
    fn a_project_swapped_mid_sync_is_refused_before_publication() {
        // Same lock order as `failed_tailor_sync_clears_its_unpublished_exceptions`.
        let _env_lock = policy::test_env_lock();
        let temp = TempDir::new();
        let home = temp.0.join("home");
        std::fs::create_dir_all(&home).unwrap();
        let _policy_env = PolicyEnv::enter(&home);
        let _store_lock = store::STORE_ENV_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let _attribution = policy::attribution_test_lock();
        let project = temp.0.join("project");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(
            project.join("pyproject.toml"),
            "[project]\nname = \"fixture\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        std::fs::write(project.join(".python-version"), "3.12.14\n").unwrap();
        let _store_env = StoreEnv::enter(&temp.0.join("store"));
        let platform = Platform::host().unwrap();
        let ctx = Context::open_in(platform, &project).unwrap();
        let root = ProjectRoot::open(&project).unwrap();
        let moved = temp.0.join("moved");
        let swapped = SwappedMidSync {
            moved: moved.clone(),
        };
        let present: [&'static dyn Tailor; 1] = [Box::leak(Box::new(swapped))];
        let mut toolchain =
            preflight_detected(platform, &root, &present, Mode::Writable, Scope::All).unwrap();

        let error = sync_preflighted(
            &ctx,
            &root,
            &present,
            &mut toolchain,
            false,
            &Mode::Writable,
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("moved or replaced during sync"),
            "{error}"
        );
        assert!(!project.join(".tog/closures/python.json").exists());
        assert!(!moved.join(".tog/closures/python.json").exists());
        assert!(
            ctx.store.roots().unwrap().is_empty(),
            "a refused publication registered a root"
        );
        assert!(
            policy::pending().is_empty(),
            "a refused publication left an exception queued"
        );
    }

    /// The same swap with no toolchain guard installed (a tailor driven
    /// outside `sync_preflighted`, as `commit` never ran): the guard's own
    /// still-named check cannot catch it, so the closure writer's check is
    /// what refuses, before a root is registered or a closure written in
    /// either directory.
    #[test]
    fn a_swapped_project_is_refused_by_the_closure_writer_without_a_guard() {
        // Same lock order as `failed_tailor_sync_clears_its_unpublished_exceptions`.
        let _env_lock = policy::test_env_lock();
        let temp = TempDir::new();
        let home = temp.0.join("home");
        std::fs::create_dir_all(&home).unwrap();
        let _policy_env = PolicyEnv::enter(&home);
        let _store_lock = store::STORE_ENV_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let _attribution = policy::attribution_test_lock();
        assert!(
            !project_toolchain::guard_installed_for_test(),
            "a toolchain guard from another command is still installed"
        );
        let project = temp.0.join("project");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(
            project.join("pyproject.toml"),
            "[project]\nname = \"fixture\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        std::fs::write(project.join(".python-version"), "3.12.14\n").unwrap();
        let _store_env = StoreEnv::enter(&temp.0.join("store"));
        let platform = Platform::host().unwrap();
        let ctx = Context::open_in(platform, &project).unwrap();
        let root = ProjectRoot::open(&project).unwrap();
        let moved = temp.0.join("moved");
        let swapped: &'static SwappedMidSync = Box::leak(Box::new(SwappedMidSync {
            moved: moved.clone(),
        }));
        // Resolve a toolchain for the request without `commit`, which is
        // what would install the guard.
        let present: [&'static dyn Tailor; 1] = [swapped];
        let toolchain =
            preflight_detected(platform, &root, &present, Mode::Writable, Scope::All).unwrap();
        assert!(!project_toolchain::guard_installed_for_test());
        let selections = std::collections::BTreeMap::new();
        let request = SyncRequest {
            fresh: false,
            toolchain: toolchain.get("python").unwrap(),
            selections: &selections,
        };
        let mut attribution = policy::Attribution::open("python").unwrap();
        let error = swapped
            .sync(&ctx, &root, &request, &mut attribution)
            .unwrap_err();
        drop(attribution);
        assert!(
            error.to_string().contains("moved or replaced during sync"),
            "{error}"
        );
        assert!(!project.join(".tog/closures/python.json").exists());
        assert!(!moved.join(".tog/closures/python.json").exists());
        assert!(
            ctx.store.roots().unwrap().is_empty(),
            "a refused publication registered a root"
        );
    }
}

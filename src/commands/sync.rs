//! The bare `tog` (hidden alias `sync`): preflight every detected
//! ecosystem, then plan, realize, and project each one through the tailor
//! registry.

use crate::comforter::toolchain::{self as project_toolchain, Mode, ProjectToolchain};
use crate::commands::shared::{ecosystem_inputs, no_inputs, projected_root};
use crate::kernel::context::{self, Context};
use crate::kernel::fsroot::ProjectRoot;
use crate::kernel::platform::Platform;
use crate::kernel::policy;
use crate::kernel::store;
use crate::tailors::{self, SyncRequest, Tailor};
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// Check every detected ecosystem can sync, touching no store. Returns the
/// tailors it checked, so the sync runs exactly those, and the toolchain
/// each one must use.
///
/// Resolution happens here, before the store is opened: a stale or
/// unresolvable toolchain must refuse without creating a store tree, taking
/// a lease, or running maintenance. Nothing is written yet either; `commit`
/// publishes a created lock once the store lease is held.
pub fn preflight_sync(
    platform: Platform,
    dir: &Path,
    mode: Mode,
) -> io::Result<(Vec<&'static dyn Tailor>, ProjectToolchain)> {
    // Syncing ends by registering this project as a GC root. Check that the
    // path can be recorded before realizing or projecting anything: a
    // finished sync that could not register would leave a projected
    // environment nothing protects, and the next sweep would collect it.
    store::Store::check_registrable(dir)?;
    let present = tailors::detected(dir)?;
    // No project is the answer before any lock is: `tog --frozen` in the
    // wrong directory must say there is no manifest here, not that
    // tog-toolchain.toml is missing.
    if present.is_empty() {
        return Err(no_inputs());
    }
    // The declarative inputs and the lock are read through the held root
    // descriptor, so a tampered input or lock fails closed here. Only
    // detected ecosystems are consulted, so a stray symlink for an ecosystem
    // the project does not use cannot stop its sync.
    let root = ProjectRoot::open(dir)?;
    // Host support first: an ecosystem that cannot run here at all says so
    // in its own words, before selection reports the same project as
    // unsatisfiable in the catalog's words.
    for tailor in &present {
        tailor.preflight(platform, dir)?;
    }
    let inputs = ecosystem_inputs(dir, &present)?;
    let toolchain = project_toolchain::resolve(&root, platform, inputs, mode, policy::strict())?;
    Ok((present, toolchain))
}

/// The bare `tog` from the command line: load policy and preflight every
/// ecosystem before the store is opened. A refused request (an unpinned
/// patch, a path no root record can hold) must leave no trace: no store
/// tree created, no maintenance sweep, no lease taken.
pub fn run_command(platform: Platform, fresh: bool, strict: bool, frozen: bool) -> io::Result<()> {
    let mode = if frozen { Mode::Frozen } else { Mode::Writable };
    run_in_mode(platform, fresh, strict, mode, false)
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
    strict: bool,
    mode: Mode,
    stop_after_lock: bool,
) -> io::Result<()> {
    let dir = context::project_dir();
    let checked = directory_identity(&dir)?;
    let (present, mut toolchain) = preflight(platform, &dir, strict, mode.clone())?;
    // Opening the store can wait on another process's lease. If the
    // directory was renamed or replaced meanwhile, the pathname no longer
    // names the project preflight checked: refuse rather than sync it. This
    // closes the wait this ordering added, not every pathname race: the
    // sync itself reads the project by path, as it always has.
    let ctx = Context::open(platform, true)?;
    let moved = |detail: String| {
        io::Error::other(format!(
            "{}: {detail} while waiting for the store; run 'tog' again",
            dir.display()
        ))
    };
    match directory_identity(&dir) {
        Ok(now) if now == checked => {}
        Ok(_) => return Err(moved("the project directory was moved or replaced".into())),
        Err(error) => {
            return Err(moved(format!(
                "the project directory became unreadable ({error})"
            )))
        }
    }
    if stop_after_lock {
        if present.is_empty() {
            return Err(no_inputs());
        }
        let root = ProjectRoot::open(&dir)?;
        let _input_lock = project_toolchain::commit(&root, &mut toolchain, &mode)?;
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
            let root = ProjectRoot::open(&dir)?;
            let _published = project_toolchain::commit(&root, &mut toolchain, &mode)?;
        }
        let (present, mut toolchain) = preflight_sync(platform, &dir, Mode::Writable)?;
        return sync_preflighted(&ctx, &dir, &present, &mut toolchain, fresh, &Mode::Writable);
    }
    sync_preflighted(&ctx, &dir, &present, &mut toolchain, fresh, &mode)
}

fn directory_identity(dir: &Path) -> io::Result<(u64, u64)> {
    let metadata = std::fs::metadata(dir)?;
    Ok((metadata.dev(), metadata.ino()))
}

/// Sync with a context the caller already opened (`add`/`remove`/`update`
/// after their manifest edit).
pub fn run(ctx: &Context, fresh: bool, strict: bool) -> io::Result<()> {
    run_in(ctx, &ctx.project_dir(), fresh, strict, false)
}

/// The same sync of one named directory: the projected root a command
/// found by walking up, which is not always the process cwd.
fn run_in(ctx: &Context, dir: &Path, fresh: bool, strict: bool, frozen: bool) -> io::Result<()> {
    let mode = if frozen { Mode::Frozen } else { Mode::Writable };
    let (present, mut toolchain) = preflight(ctx.platform, dir, strict, mode.clone())?;
    sync_preflighted(ctx, dir, &present, &mut toolchain, fresh, &mode)
}

/// Sync first when the environment for `cwd` is not the one its inputs
/// describe, and return the root whose projection the caller should read.
///
/// `tog run`, `tog env` and a delegated `tog fmt` script all want the
/// environment the project's inputs describe. Refusing with "run `tog
/// sync` first" made the user type the one thing tog already knew to do.
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
pub(crate) fn ensure_current(
    ctx: &Context,
    cwd: &Path,
    frozen: bool,
    strict: bool,
) -> io::Result<PathBuf> {
    ensure_current_for(ctx, cwd, None, frozen, strict)
}

/// `ensure_current`, deciding on one ecosystem's row only when `only`
/// names it. `build` uses one environment, so a stale or broken ecosystem
/// it does not build (a Python docs tool in a Rust repo) does not start a
/// sync in front of it. When the built ecosystem is stale the sync still
/// resolves the toolchain lock for every ecosystem, so the committed lock
/// stays whole, but only the built ecosystem is prepared and realized: an
/// unrelated one that cannot sync (offline, a broken install script, a
/// CPython with no pinned build) no longer stops the build.
pub(crate) fn ensure_current_for(
    ctx: &Context,
    cwd: &Path,
    only: Option<&str>,
    frozen: bool,
    strict: bool,
) -> io::Result<PathBuf> {
    let dir = sync_root(cwd)?;
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
            Some(ecosystem) => run_in_only(ctx, &dir, strict, frozen, ecosystem)?,
            None => run_in(ctx, &dir, false, strict, frozen)?,
        }
    }
    Ok(projected_root(cwd))
}

/// The build's sync: preflight and resolve the whole project, so the lock
/// `commit` publishes still names every detected ecosystem, but prepare
/// and realize the named tailor only. Filtering after `commit` is what
/// keeps the lock whole: resolving a subset would publish a lock with the
/// other sections truncated.
fn run_in_only(
    ctx: &Context,
    dir: &Path,
    strict: bool,
    frozen: bool,
    only: &str,
) -> io::Result<()> {
    let mode = if frozen { Mode::Frozen } else { Mode::Writable };
    let (present, mut toolchain) = preflight(ctx.platform, dir, strict, mode.clone())?;
    let scoped = scope_to(&present, only);
    sync_preflighted(ctx, dir, &scoped, &mut toolchain, false, &mode)
}

/// The tailors one sync realizes: every detected one, or the named one.
/// `only` always names a tailor the caller resolved first (the ecosystem
/// being built), so it is present here; anything else scopes to nothing,
/// and the empty slice fails closed in `sync_preflighted` (`no_inputs`).
fn scope_to<'a>(present: &[&'a dyn Tailor], only: &str) -> Vec<&'a dyn Tailor> {
    present
        .iter()
        .filter(|tailor| tailor.id() == only)
        .copied()
        .collect()
}

/// The directory a command's sync belongs to: the nearest projected
/// ancestor, as `run` has always found it, and otherwise the nearest
/// ancestor with a manifest, so `tog run` from `src/` of a never-synced
/// project finds the project. The projected walk comes first, so a nested
/// package.json under an already-synced root (a docs site) keeps
/// belonging to that root.
fn sync_root(cwd: &Path) -> io::Result<PathBuf> {
    if let Some(projected) = cwd.ancestors().find(|d| d.join(".tog/closures").is_dir()) {
        return Ok(projected.to_path_buf());
    }
    for dir in cwd.ancestors() {
        if !crate::commands::inspect::detected(dir)?.is_empty() {
            return Ok(dir.to_path_buf());
        }
    }
    Ok(cwd.to_path_buf())
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
    dir: &Path,
    strict: bool,
    mode: Mode,
) -> io::Result<(Vec<&'static dyn Tailor>, ProjectToolchain)> {
    policy::init(dir, strict)?;
    // A configured signing key that cannot be loaded fails here, before the
    // store is opened or any closure is written.
    crate::comforter::init_signing()?;
    preflight_sync(platform, dir, mode)
}

pub(crate) fn sync_preflighted(
    ctx: &Context,
    dir: &Path,
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
    let root = ProjectRoot::open(dir)?;
    let _input_lock = project_toolchain::commit(&root, toolchain, mode)?;
    let frozen = *mode == Mode::Frozen;
    let mut any = false;
    for tailor in present {
        let selected = toolchain.get(tailor.lock_ecosystem())?;
        let mut attribution = policy::Attribution::open(tailor.id())?;
        // `prepare` is missing-lock generation: it runs the ecosystem's own
        // tool in the project and writes a dependency lock. Frozen promises
        // not to modify project inputs, so it never reaches that call at
        // all; a project with no dependency lock fails inside the tailor,
        // which is the one place that knows which file is missing.
        if !frozen {
            tailor.prepare(ctx, dir, selected, &mut attribution)?;
        }
        let request = SyncRequest {
            fresh,
            frozen,
            toolchain: selected,
        };
        let changed = tailor.sync(ctx, dir, &request, &mut attribution)?;
        attribution.finish(changed)?;
        if changed {
            any = true;
        }
    }
    if !any {
        return Err(no_inputs());
    }
    print_exception_summary(dir)?;
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

fn print_exception_summary(project_dir: &Path) -> io::Result<()> {
    let dir = project_dir.join(".tog/closures");
    let mut total = 0;
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            if !entry.file_name().to_string_lossy().ends_with(".json") {
                continue;
            }
            let text = match std::fs::read_to_string(entry.path()) {
                Ok(text) => text,
                Err(_) => continue,
            };
            let value: serde_json::Value = match serde_json::from_str(&text) {
                Ok(value) => value,
                Err(_) => continue,
            };
            total += value["body"]["exceptions"].as_array().map_or(0, Vec::len);
        }
    }
    match exception_summary(total, policy::signing_configured()) {
        Some((message, Some(fix))) => crate::kernel::ui::warning(&message, fix),
        Some((message, None)) => crate::kernel::ui::note(&message),
        None => {}
    }
    Ok(())
}

/// A count and where to read it. The line this replaces advised `tog
/// --strict`, which does not refuse the recorded exceptions: it fails the
/// sync that recorded them, undoing the work that just finished.
///
/// It is a warning with `tog audit` as its fix only where an audit gate is
/// configured (a `[signing]` table with trusted keys): `audit` refuses to
/// run without one, and unsigned closures are not judged, so without a
/// gate there is nothing to type and the count is progress.
fn exception_summary(total: usize, gate: bool) -> Option<(String, Option<&'static str>)> {
    (total > 0).then(|| {
        let message = format!("{total} policy exception(s) recorded in .tog/closures/*.json");
        if gate {
            (message, Some("tog audit"))
        } else {
            (
                format!(
                    "{message}; a policy with [signing] trusted keys makes 'tog audit' judge them"
                ),
                None,
            )
        }
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
        let store = store::Store {
            root: temp.0.clone(),
        };
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
        let store = store::Store {
            root: temp.0.clone(),
        };
        assert!(claim_habits_notice(&store, false));
        assert!(!claim_habits_notice(&store, false));

        // Quiet would drop the line on the way out, so it never spends the
        // showing: a fresh store is left unclaimed for a loud run.
        let quiet_temp = TempDir::new();
        let quiet_store = store::Store {
            root: quiet_temp.0.clone(),
        };
        assert!(!claim_habits_notice(&quiet_store, true));
        assert!(!quiet_store.root.join("habits-notice").exists());
        assert!(claim_habits_notice(&quiet_store, false));

        // A store that cannot be written stays quiet rather than nagging.
        let unwritable = store::Store {
            root: temp.0.join("no/such/store"),
        };
        assert!(!claim_habits_notice(&unwritable, false));
    }

    /// `tog --strict` does not refuse recorded exceptions; it fails
    /// the sync that recorded them. The summary must not advise it.
    #[test]
    fn the_exception_summary_counts_and_points_at_a_read_command() {
        assert_eq!(exception_summary(0, true), None);
        assert_eq!(exception_summary(0, false), None);
        let (line, fix) = exception_summary(3, true).unwrap();
        assert!(line.starts_with("3 policy exception(s) recorded"), "{line}");
        assert!(line.contains(".tog/closures/*.json"), "{line}");
        assert_eq!(fix, Some("tog audit"));
        assert!(!line.contains("--strict"), "{line}");
        // Without a gate `tog audit` refuses to run, so there is nothing to
        // type: the count is progress and names what would change that.
        let (line, fix) = exception_summary(3, false).unwrap();
        assert_eq!(fix, None);
        assert!(line.contains("[signing]"), "{line}");
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
        let Err(error) = preflight_sync(Platform::host().unwrap(), &project, Mode::Writable) else {
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
        // it. The order is the one this file documents: supervision, then
        // attribution.
        let _supervision = crate::kernel::supervise::SUPERVISION_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
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
        let (present, mut toolchain) = preflight_sync(platform, &project, Mode::Writable).unwrap();
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

        let (_, again) = preflight_sync(platform, &project, Mode::Writable).unwrap();
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
        let Err(error) = preflight_sync(Platform::host().unwrap(), &project, Mode::Writable) else {
            panic!("a symlinked .python-version was read through");
        };
        assert!(error.to_string().contains("is a symlink"), "{error}");
        // The same symlink for an ecosystem the project does not use is
        // not consulted.
        std::fs::remove_file(project.join(".python-version")).unwrap();
        std::fs::write(project.join(".python-version"), "3.12.14\n").unwrap();
        std::os::unix::fs::symlink(&victim, project.join(".ruby-version")).unwrap();
        preflight_sync(Platform::host().unwrap(), &project, Mode::Writable).unwrap();
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
        let _supervision = crate::kernel::supervise::SUPERVISION_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
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
        let ctx = Context::open_in(Platform::host().unwrap(), &bare, false).unwrap();

        let root = ensure_current(&ctx, &bare, false, false)
            .expect("a directory with no manifest is left alone");
        assert_eq!(root, bare);
        assert!(!bare.join(".tog").exists());

        let error = ensure_current(&ctx, &project, false, false).unwrap_err();
        assert!(error.to_string().contains("no pinned CPython"), "{error}");
        // From a subdirectory the manifest above is the project.
        let error = ensure_current(&ctx, &nested, false, false).unwrap_err();
        assert!(error.to_string().contains("no pinned CPython"), "{error}");
        assert_eq!(sync_root(&nested).unwrap(), project);
        assert_eq!(sync_root(&bare).unwrap(), bare);
    }

    /// The build's sync realizes the built ecosystem only: with two
    /// ecosystems detected, scoping to one leaves the other out. The lock
    /// stays whole regardless, because `commit` publishes the full pending
    /// toolchain whatever slice the tailor loop is given.
    #[test]
    fn build_sync_scopes_to_the_built_ecosystem() {
        let present = tailors::registry();
        assert!(present.len() > 1, "needs two ecosystems to scope");
        let scoped = scope_to(present, "cargo");
        assert_eq!(scoped.len(), 1);
        assert_eq!(scoped[0].id(), "cargo");
        assert!(scoped.iter().all(|tailor| tailor.id() != "python"));
        // An unknown name scopes to nothing, which fails closed downstream
        // (`sync_preflighted` refuses an empty slice).
        assert!(scope_to(present, "cobol").is_empty());
    }

    #[test]
    fn failed_tailor_sync_clears_its_unpublished_exceptions() {
        // Process-global test state follows env -> supervision -> store ->
        // attribution. Every multi-guard holder takes them in this order:
        // commands::deps (supervision -> store -> attribution),
        // commands::inspect's doctor tests (env -> store), the comforter
        // writer tests (supervision -> attribution), kernel::gitsrc and the
        // tailors (supervision). One shared total order, so no holder can
        // wait on a lock another holder has taken after an earlier one.
        let _env_lock = policy::test_env_lock();
        let temp = TempDir::new();
        let home = temp.0.join("home");
        std::fs::create_dir_all(&home).unwrap();
        let _policy_env = PolicyEnv::enter(&home);
        let _supervision = crate::kernel::supervise::SUPERVISION_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
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
        let ctx = Context::open_in(Platform::host().unwrap(), &project, false).unwrap();

        let error = run(&ctx, false, false).unwrap_err();
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
}

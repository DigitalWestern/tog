//! `tog sync`: preflight every detected ecosystem, then plan, realize,
//! and project each one through the tailor registry.

use crate::commands::shared::no_inputs;
use crate::kernel::context::{self, Context};
use crate::kernel::platform::Platform;
use crate::kernel::policy;
use crate::kernel::store;
use crate::tailors::{self, Tailor};
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

/// Check every detected ecosystem can sync, touching no store. Returns the
/// tailors it checked so the sync runs exactly those.
pub fn preflight_sync(platform: Platform, dir: &Path) -> io::Result<Vec<&'static dyn Tailor>> {
    // Syncing ends by registering this project as a GC root. Check that the
    // path can be recorded before realizing or projecting anything: a
    // finished sync that could not register would leave a projected
    // environment nothing protects, and the next sweep would collect it.
    store::Store::check_registrable(dir)?;
    let present = tailors::detected(dir)?;
    for tailor in &present {
        tailor.preflight(platform, dir)?;
    }
    Ok(present)
}

/// `tog sync` from the command line: load policy and preflight every
/// ecosystem before the store is opened. A refused request (an unpinned
/// patch, a path no root record can hold) must leave no trace: no store
/// tree created, no maintenance sweep, no lease taken.
pub fn run_command(platform: Platform, fresh: bool, strict: bool) -> io::Result<()> {
    let dir = context::project_dir();
    let checked = directory_identity(&dir)?;
    let present = preflight(platform, &dir, strict)?;
    // Opening the store can wait on another process's lease. If the
    // directory was renamed or replaced meanwhile, the pathname no longer
    // names the project preflight checked: refuse rather than sync it. This
    // closes the wait this ordering added, not every pathname race: the
    // sync itself reads the project by path, as it always has.
    let ctx = Context::open(platform, true)?;
    let moved = |detail: String| {
        io::Error::other(format!(
            "{}: {detail} while waiting for the store; run 'tog sync' again",
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
    sync_preflighted(&ctx, &dir, &present, fresh)
}

fn directory_identity(dir: &Path) -> io::Result<(u64, u64)> {
    let metadata = std::fs::metadata(dir)?;
    Ok((metadata.dev(), metadata.ino()))
}

/// Sync with a context the caller already opened (`add`/`remove`/`update`
/// after their manifest edit).
pub fn run(ctx: &Context, fresh: bool, strict: bool) -> io::Result<()> {
    let dir = ctx.project_dir();
    let present = preflight(ctx.platform, &dir, strict)?;
    sync_preflighted(ctx, &dir, &present, fresh)
}

fn preflight(platform: Platform, dir: &Path, strict: bool) -> io::Result<Vec<&'static dyn Tailor>> {
    policy::init(dir, strict)?;
    // A configured signing key that cannot be loaded fails here, before the
    // store is opened or any closure is written.
    crate::comforter::init_signing()?;
    preflight_sync(platform, dir)
}

fn sync_preflighted(
    ctx: &Context,
    dir: &Path,
    present: &[&'static dyn Tailor],
    fresh: bool,
) -> io::Result<()> {
    let mut any = false;
    for tailor in present {
        let mut attribution = policy::Attribution::open(tailor.id())?;
        tailor.prepare(ctx, dir, &mut attribution)?;
        let changed = tailor.sync(ctx, dir, fresh, &mut attribution)?;
        attribution.finish(changed)?;
        if changed {
            any = true;
        }
    }
    if !any {
        return Err(no_inputs());
    }
    print_exception_summary(dir)?;
    if crate::comforter::signing_key().is_none() {
        eprintln!(
            "tog: closures unsigned; tog audit reports them outdated \
             (set TOG_SIGNING_KEY=<key file> to sign; 'tog keygen' makes one)"
        );
    }
    Ok(())
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
    if total > 0 {
        eprintln!(
            "tog: {total} exception(s) recorded in .tog/closures/*.json — \
             `tog sync --strict` to refuse them"
        );
    }
    Ok(())
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

    /// Sync ends by registering the project as a GC root, so a path no
    /// record can hold is refused before an environment is realized or
    /// projected. Refusing at the end instead would leave the project synced,
    /// unprotected and with no way to register it.
    #[test]
    fn sync_refuses_a_project_path_no_root_record_can_hold() {
        let temp = TempDir::new();
        let project = temp.0.join("project ");
        std::fs::create_dir_all(&project).unwrap();
        let Err(error) = preflight_sync(Platform::host().unwrap(), &project) else {
            panic!("an unregistrable project path was accepted");
        };
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("cannot protect"), "{error}");
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

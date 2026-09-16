//! `blanket sync`: preflight every detected ecosystem, then plan, realize,
//! and project each one through the tailor registry.

use crate::commands::shared::no_inputs;
use crate::kernel::context::Context;
use crate::kernel::platform::Platform;
use crate::kernel::policy;
use crate::kernel::store;
use crate::tailors;
use std::io;
use std::path::Path;

pub fn preflight_sync(platform: Platform, dir: &Path) -> io::Result<()> {
    // Syncing ends by registering this project as a GC root. Check that the
    // path can be recorded before realizing or projecting anything: a
    // finished sync that could not register would leave a projected
    // environment nothing protects, and the next sweep would collect it.
    store::Store::check_registrable(dir)?;
    for tailor in tailors::detected(dir)? {
        tailor.preflight(platform, dir)?;
    }
    Ok(())
}

pub fn run(ctx: &Context, fresh: bool, strict: bool) -> io::Result<()> {
    let dir = ctx.project_dir();
    policy::init(&dir, strict)?;
    preflight_sync(ctx.platform, &dir)?;
    let present = tailors::detected(&dir)?;
    let mut any = false;
    for tailor in &present {
        let mut attribution = policy::Attribution::open(tailor.id())?;
        tailor.prepare(ctx, &dir, &mut attribution)?;
        let changed = tailor.sync(ctx, &dir, fresh, &mut attribution)?;
        attribution.finish(changed)?;
        if changed {
            any = true;
        }
    }
    if !any {
        return Err(no_inputs());
    }
    print_exception_summary(&dir)?;
    Ok(())
}

fn print_exception_summary(project_dir: &Path) -> io::Result<()> {
    let dir = project_dir.join(".blanket/closures");
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
            "blanket: {total} exception(s) recorded in .blanket/closures/*.json — \
             `blanket sync --strict` to refuse them"
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
            let old = std::env::var_os("BLANKET_STORE");
            std::env::set_var("BLANKET_STORE", path);
            Self(old)
        }
    }

    impl Drop for StoreEnv {
        fn drop(&mut self) {
            match self.0.take() {
                Some(value) => std::env::set_var("BLANKET_STORE", value),
                None => std::env::remove_var("BLANKET_STORE"),
            }
        }
    }

    struct PolicyEnv {
        home: Option<OsString>,
        policy: Option<OsString>,
        strict: Option<OsString>,
    }

    impl PolicyEnv {
        fn enter(home: &Path) -> Self {
            let old = Self {
                home: std::env::var_os("HOME"),
                policy: std::env::var_os("BLANKET_POLICY"),
                strict: std::env::var_os("BLANKET_STRICT"),
            };
            std::env::set_var("HOME", home);
            std::env::remove_var("BLANKET_POLICY");
            std::env::remove_var("BLANKET_STRICT");
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
                Some(value) => std::env::set_var("BLANKET_POLICY", value),
                None => std::env::remove_var("BLANKET_POLICY"),
            }
            match self.strict.take() {
                Some(value) => std::env::set_var("BLANKET_STRICT", value),
                None => std::env::remove_var("BLANKET_STRICT"),
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
        let error = preflight_sync(Platform::host().unwrap(), &project).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("cannot protect"), "{error}");
    }

    #[test]
    fn failed_tailor_sync_clears_its_unpublished_exceptions() {
        // Process-global test state follows env -> supervision -> store ->
        // attribution. No other test acquires these four guards in a
        // conflicting order.
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

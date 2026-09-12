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
    for tailor in &present {
        tailor.prepare(ctx, &dir)?;
    }
    let mut any = false;
    for tailor in &present {
        if tailor.sync(ctx, &dir, fresh)? {
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
}

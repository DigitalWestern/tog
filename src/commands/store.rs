//! `tog store roots` / `tog store path`: read-only store diagnostics.
//! Kernel only; work without a valid host platform.

use crate::kernel::activity::ActivityMode;
use crate::kernel::store;
use crate::kernel::ui;
use std::io;

pub fn roots() -> io::Result<()> {
    print!("{}", list_roots(&store::Store::open()?)?);
    Ok(())
}

/// The lines `tog store roots` prints for `store`, read under a shared
/// lease. The lease validates the format marker again once it is held: a
/// store that was emptied, or left half emptied, between this command
/// opening it and reading it is refused, not listed.
// Reviewed site (tests/architecture.rs): operation boundary: command entry point.
#[allow(clippy::disallowed_methods)]
fn list_roots(store: &store::Store) -> io::Result<String> {
    let activity = store.activity(ActivityMode::Shared)?;
    let mut lines = String::new();
    for root in store.root_diagnostics(&activity)? {
        lines.push_str(&match (root.path, root.problem) {
            (Some(path), None) => format!("{}  {}\n", root.key, path.display()),
            (_, Some(problem)) => format!("{}  <invalid: {}>\n", root.key, problem),
            _ => format!("{}  <invalid root record>\n", root.key),
        });
    }
    Ok(lines)
}

pub fn path() -> io::Result<i32> {
    // A store this tog refuses to open still has a path, and the path is
    // what someone moving it aside needs: print it, and say on stderr why
    // nothing else will use it.
    if let Some((root, format)) = store::Store::probe()? {
        if let Some(refusal) = format.refusal(&root) {
            println!("{}", root.display());
            ui::warning(&refusal, &format.fix_for(&root));
            return Ok(0);
        }
    }
    let store = store::Store::open()?;
    println!("{}", store.root.display());
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::testutil::TempDir;
    use std::fs;

    /// A reset that stops after it removed the marker and the objects
    /// leaves root records behind. A `store roots` that had already opened
    /// the store must refuse at its lease: it lists none of those records
    /// and does not put back a namespace the reset removed.
    #[test]
    fn roots_refuses_a_store_a_reset_left_half_emptied() {
        let temp = TempDir::named("store-roots-interrupted");
        let opened = store::Store::open_at(&temp.0.join("store")).unwrap();
        let project = temp.0.join("project");
        fs::create_dir_all(&project).unwrap();
        opened.register_root(&project).unwrap();
        let listed = list_roots(&opened).unwrap();
        assert!(listed.contains(&project.display().to_string()), "{listed}");

        // The interrupted reset: marker gone, objects gone, roots still there.
        fs::remove_file(opened.root.join(store::FORMAT_FILE)).unwrap();
        fs::remove_dir_all(opened.root.join("objects")).unwrap();
        let error = list_roots(&opened).unwrap_err();
        assert!(
            error.to_string().contains("has no format marker"),
            "{error}"
        );
        assert!(store::refusal_fix(&error)
            .unwrap()
            .ends_with(" tog gc --reset"));

        // Further along: the roots are gone too. Nothing is recreated.
        fs::remove_dir_all(opened.root.join("roots")).unwrap();
        assert!(list_roots(&opened).is_err());
        assert!(!opened.root.join("roots").exists());
        assert!(!opened.root.join("objects").exists());
    }
}

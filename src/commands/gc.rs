//! `tog gc`: store garbage collection and root-registry maintenance.
//! Kernel only; works without a valid host platform.

use crate::cli;
use crate::kernel::gc;
use crate::kernel::store;
use crate::kernel::ui;
use std::io;
use std::io::Write;

// Reviewed site (tests/architecture.rs): operation boundary: command entry point.
#[allow(clippy::disallowed_methods)]
pub fn run(args: &cli::GcArgs) -> io::Result<()> {
    let mut options = gc::Options {
        dry_run: args.dry_run,
        project: args.project,
        keep_days: args.keep_days.unwrap_or(gc::Options::default().keep_days),
        forgotten: args.forget.clone(),
    };
    // A reset is the one gc path that must work on a store `open` refuses,
    // so it runs before the store is opened and never opens it.
    if args.reset {
        return reset(args);
    }
    let store = store::Store::open()?;
    // gc narrates; it does not produce a document. CLI.md reserves stdout
    // for results (`plan`, `sbom`, `store path`, the `--json` forms), so
    // every line below is narration, where `--quiet` can silence it.
    let mut narrate = ui::narration();
    // Option combinations were refused from argv (`cli::parse`).
    let Some(activity) = store.try_activity_exclusive()? else {
        // An explicitly requested mutation fails loudly; an opportunistic
        // sweep skips quietly.
        if !args.forget.is_empty() || !args.drop_objects.is_empty() {
            return Err(io::Error::other(
                "a Tog job is using this store; retry when it finishes",
            ));
        }
        writeln!(
            narrate,
            "tog: cleanup skipped: a Tog job is using this store"
        )?;
        return Ok(());
    };
    // Dropping is a targeted removal, not a sweep and not a registry edit.
    // It shares only `--dry-run`, which every destructive path here honours.
    if !args.drop_objects.is_empty() {
        gc::drop_objects(
            &store,
            &activity,
            &args.drop_objects,
            args.dry_run,
            &mut narrate,
        )?;
        return Ok(());
    }
    // Resolve every key before changing the registry. This keeps a typo or
    // unknown key from partially applying a multi-key forget request.
    for (index, key) in args.forget.iter().enumerate() {
        let key = store.lookup_root(key)?.key;
        if options.forgotten[..index]
            .iter()
            .any(|previous| previous == &key)
        {
            return Err(io::Error::other(format!(
                "refusing to forget root key {key} more than once in one invocation"
            )));
        }
        // The sweep compares the record's on-disk name; on a
        // case-insensitive filesystem the key may have been typed in
        // another case (#163).
        options.forgotten[index] = key;
    }
    // Compare resolved registry identities before either operation writes.
    // Distinct spellings remain distinct on a case-sensitive filesystem.
    for project in &args.register {
        let key = store::Store::root_key(project)?;
        let key = match store.lookup_root(&key) {
            Ok(entry) => entry.key,
            Err(error) if error.kind() == io::ErrorKind::NotFound => key,
            Err(error) => return Err(error),
        };
        if options.forgotten.iter().any(|forget| forget == &key) {
            return Err(io::Error::other(format!(
                "refusing to register and forget the same root key {key} in one invocation"
            )));
        }
    }
    // `--dry-run` with `--register` was refused from argv.
    for project in &args.register {
        let entry = store.register_root_from_project_with_activity(&activity, project)?;
        writeln!(narrate, "tog: registered root {}", entry.path.display())?;
    }
    for key in &options.forgotten {
        if options.dry_run {
            let entry = store.lookup_root(key)?;
            writeln!(
                narrate,
                "tog: would forget root {key} ({})",
                entry.describe()
            )?;
        } else {
            let entry = store.forget_root_with_activity(&activity, key)?;
            writeln!(narrate, "tog: forgot root {key} ({})", entry.describe())?;
        }
    }
    // Forgetting is the explicit recovery action, not an implicit sweep. A
    // later `tog gc` may collect objects that are no longer protected;
    // this invocation must only change the requested registry records.
    if !options.dry_run && !args.forget.is_empty() {
        return Ok(());
    }
    let dry_run = options.dry_run;
    let report = gc::collect_with_activity(&store, &activity, options, &mut narrate)?;
    let verb = if dry_run { "would free" } else { "freed" };
    writeln!(
        narrate,
        "tog: gc {verb} {} MB ({} objects, {} cached artifacts)",
        report.freed_bytes / (1024 * 1024),
        report.objects,
        report.cached_artifacts
    )?;
    Ok(())
}

/// `tog gc --reset`: empty the store and start it again.
// Reviewed site (tests/architecture.rs): operation boundary: command entry point.
#[allow(clippy::disallowed_methods)]
fn reset(args: &cli::GcArgs) -> io::Result<()> {
    let mut narrate = ui::narration();
    // Only the root is located: a reset reads no record and no marker, so a
    // marker that cannot even be read does not stop it.
    let Some(root) = store::Store::locate()? else {
        // No directory yet: a new store is already what a reset leaves.
        if !args.dry_run {
            store::Store::open()?;
        }
        writeln!(narrate, "tog: gc --reset: there is no store to empty yet")?;
        return Ok(());
    };
    // A handle on the root alone. The store may be one `open` refuses.
    let store = store::Store::handle(root);
    // A reset is a requested mutation: it fails loudly rather than skipping
    // when another job holds the store.
    let Some(activity) = store.try_activity_exclusive_unchecked()? else {
        return Err(io::Error::other(
            "a Tog job is using this store; retry when it finishes",
        ));
    };
    let report = gc::reset(&store, &activity, args.dry_run, &mut narrate)?;
    if args.dry_run {
        writeln!(
            narrate,
            "tog: gc --reset would free {} MB ({} objects) and keep the download cache",
            report.freed_bytes / (1024 * 1024),
            report.objects
        )?;
    } else {
        writeln!(
            narrate,
            "tog: gc --reset freed {} MB ({} objects) and kept the download cache; run 'tog' \
             in each project to rebuild what it needs",
            report.freed_bytes / (1024 * 1024),
            report.objects
        )?;
    }
    Ok(())
}

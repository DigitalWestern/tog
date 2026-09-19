//! `tog gc`: store garbage collection and root-registry maintenance.
//! Kernel only; works without a valid host platform.

use crate::cli;
use crate::kernel::gc;
use crate::kernel::store;
use std::io;
use std::io::Write;

pub fn run(args: &cli::GcArgs) -> io::Result<()> {
    let options = gc::Options {
        dry_run: args.dry_run,
        project: args.project,
        collect_legacy: args.collect_legacy,
        keep_days: args.keep_days.unwrap_or(gc::Options::default().keep_days),
        forgotten: args.forget.clone(),
    };
    let store = store::Store::open()?;
    let mut stdout = io::stdout().lock();
    // A dry run writes nothing and registration is a write, so the two
    // cannot both be honoured. Previewing the sweep as though the project
    // were registered would mean protecting a root with no record, which is
    // exactly the resolution rule GC is not allowed to bend; refuse the
    // combination instead of half-keeping either promise.
    if args.dry_run && !args.register.is_empty() {
        return Err(io::Error::other(
            "refusing to combine --dry-run with --register: registering writes a record and a \
             dry run writes nothing. Register the project, then preview with `tog gc \
             --dry-run`",
        ));
    }
    let Some(activity) = store.try_activity_exclusive()? else {
        // An explicitly requested mutation fails loudly; an opportunistic
        // sweep skips quietly. Migration is a requested mutation: a script
        // must be able to tell "migrated" from "never ran".
        if !args.forget.is_empty() || args.migrate_metadata || !args.drop_objects.is_empty() {
            return Err(io::Error::other(
                "a Tog job is using this store; retry when it finishes",
            ));
        }
        writeln!(stdout, "cleanup skipped: a Tog job is using this store")?;
        return Ok(());
    };
    // Dropping is a targeted removal, not a sweep and not a registry edit.
    // It shares only `--dry-run`, which every destructive path here honours.
    if !args.drop_objects.is_empty() {
        if args.project
            || args.collect_legacy
            || args.migrate_metadata
            || !args.register.is_empty()
            || !args.forget.is_empty()
            || args.keep_days.is_some()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "--drop-object cannot be combined with other gc options",
            ));
        }
        gc::drop_objects(
            &store,
            &activity,
            &args.drop_objects,
            args.dry_run,
            &mut stdout,
        )?;
        return Ok(());
    }
    if args.migrate_metadata {
        if args.project
            || args.collect_legacy
            || !args.register.is_empty()
            || !args.forget.is_empty()
            || args.keep_days.is_some()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "--migrate-metadata cannot be combined with registry or collection options",
            ));
        }
        let report = gc::migrate_metadata(&store, &activity, args.dry_run, &mut stdout)?;
        if report.unresolved != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "metadata migration left unresolved records; no sweep was started",
            ));
        }
        return Ok(());
    }
    // Registering and forgetting the same root in one invocation is
    // ambiguous; compare the keys before either side touches the registry.
    for project in &args.register {
        let key = store::Store::root_key(project)?;
        if args.forget.iter().any(|forget| forget == &key) {
            return Err(io::Error::other(format!(
                "refusing to register and forget the same root key {key} in one invocation"
            )));
        }
    }
    // Resolve every key before changing the registry. This keeps a typo or
    // unknown key from partially applying a multi-key forget request.
    for (index, key) in args.forget.iter().enumerate() {
        if args.forget[..index].iter().any(|previous| previous == key) {
            return Err(io::Error::other(format!(
                "refusing to forget root key {key} more than once in one invocation"
            )));
        }
        store.lookup_root(key)?;
    }
    for project in &args.register {
        if options.dry_run {
            let record = store.root_record_from_project(project)?;
            writeln!(
                stdout,
                "tog: would register root {} ({} objects)",
                record.project_path.display(),
                record.objects.len()
            )?;
        } else {
            let entry = store.register_root_from_project_with_activity(&activity, project)?;
            writeln!(stdout, "tog: registered root {}", entry.path.display())?;
        }
    }
    for key in &args.forget {
        if options.dry_run {
            let entry = store.lookup_root(key)?;
            writeln!(
                stdout,
                "tog: would forget root {key} ({})",
                entry.describe()
            )?;
        } else {
            let entry = store.forget_root_with_activity(&activity, key)?;
            writeln!(stdout, "tog: forgot root {key} ({})", entry.describe())?;
        }
    }
    // Forgetting is the explicit recovery action, not an implicit sweep. A
    // later `tog gc` may collect objects that are no longer protected;
    // this invocation must only change the requested registry records.
    if !options.dry_run && !args.forget.is_empty() {
        return Ok(());
    }
    let dry_run = options.dry_run;
    let report = gc::collect_with_activity(&store, &activity, options, &mut stdout)?;
    let verb = if dry_run { "would free" } else { "freed" };
    writeln!(
        stdout,
        "tog: gc {verb} {} MB ({} objects, {} cached artifacts)",
        report.freed_bytes / (1024 * 1024),
        report.objects,
        report.cached_artifacts
    )?;
    Ok(())
}

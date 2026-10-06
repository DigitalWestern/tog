//! Importing the object and projection references a project's closures
//! state into its root record: the strict rule for what a producer writes,
//! and the best-effort import of historical closures (`ImportMode`).

use super::*;
use crate::kernel::fsroot::{Entry, ProjectRoot};
use crate::kernel::ui;
use std::sync::OnceLock;

pub(super) fn invalid_root_import(path: &Path, detail: String) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("cannot import closure {}: {detail}", path.display()),
    )
}

pub(super) fn validate_closure_envelope<'a>(
    value: &'a serde_json::Value,
    path: &Path,
) -> io::Result<&'a serde_json::Value> {
    if value.get("schema").and_then(serde_json::Value::as_str) != Some("closure/1") {
        return Err(invalid_root_import(path, "unknown closure schema".into()));
    }
    let ecosystem = value
        .get("ecosystem")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| invalid_root_import(path, "missing closure ecosystem".into()))?;
    if !known_ecosystem(ecosystem) {
        return Err(invalid_root_import(
            path,
            format!("unknown closure ecosystem {ecosystem}"),
        ));
    }
    value
        .get("body")
        .ok_or_else(|| invalid_root_import(path, "missing closure body".into()))
}

static CLOSURE_ECOSYSTEMS: OnceLock<Vec<&'static str>> = OnceLock::new();

/// Install the ecosystems whose closures a root import accepts: every
/// tailor's id, so the kernel names none and a new tailor's closures are
/// imported without a kernel edit. The first call wins.
pub fn install_closure_ecosystems(ids: Vec<&'static str>) {
    CLOSURE_ECOSYSTEMS.get_or_init(|| ids);
}

/// Whether a tailor writes closures named `ecosystem`. Unit tests install
/// the shipped tailors' ids on first use, as every binary entry point does.
fn known_ecosystem(ecosystem: &str) -> bool {
    #[cfg(test)]
    tests::install_shipped_ecosystems();
    CLOSURE_ECOSYSTEMS
        .get()
        .is_some_and(|ids| ids.contains(&ecosystem))
}

/// How strictly a legacy closure import treats a reference it cannot
/// resolve inside this store.
///
/// An explicit `gc --register` is a request to import a specific project, so
/// an unresolvable reference is an error the user asked to hear about. An
/// import that happens automatically underneath an ordinary `sync` is not:
/// refusing there would permanently wedge the project, because the record
/// that would have to be forgotten is exactly the one that was never
/// written. A reference this store cannot resolve also protects nothing in
/// this store, so dropping it with a warning loses no retention.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ImportMode {
    Strict,
    DropUnresolvable,
}

/// Import the closures a project already has, read through the held
/// project with the strict no-follow walk: a symlinked `.tog`,
/// `.tog/closures`, or closure file is refused rather than read through, so
/// a swapped entry cannot make this record protect another project's
/// objects. An absent closures directory imports nothing; a subdirectory
/// in it is skipped, as the pathname importer skipped it.
pub(super) fn import_existing_project_closures(
    store: &Store,
    project: &ProjectRoot,
    record: &mut RootRecord,
    mode: ImportMode,
) -> io::Result<()> {
    let closures = Path::new(".tog/closures");
    let Some(names) = project.read_dir(closures)? else {
        return Ok(());
    };
    for name in names {
        let relative = closures.join(&name);
        if !is_closure_file(&relative) {
            continue;
        }
        if project.entry(&relative)? == Entry::Directory {
            continue;
        }
        let path = project.path().join(&relative);
        let Some(bytes) = project.read_file(&relative)? else {
            continue;
        };
        let value: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|error| invalid_root_import(&path, error.to_string()))?;
        let body = validate_closure_envelope(&value, &path)?;
        import_closure_refs(store, body, record, mode)?;
    }
    Ok(())
}

pub(super) fn import_closure_refs(
    store: &Store,
    body: &serde_json::Value,
    record: &mut RootRecord,
    mode: ImportMode,
) -> io::Result<()> {
    fn walk(
        store: &Store,
        value: &serde_json::Value,
        record: &mut RootRecord,
        mode: ImportMode,
    ) -> io::Result<()> {
        match value {
            serde_json::Value::String(text) => {
                import_absolute_reference(store, Path::new(text), record, mode)
            }
            serde_json::Value::Array(values) => {
                for value in values {
                    walk(store, value, record, mode)?;
                }
                Ok(())
            }
            serde_json::Value::Object(values) => {
                if let (Some(id), Some(path)) = (
                    values.get("id").and_then(serde_json::Value::as_str),
                    values.get("path").and_then(serde_json::Value::as_str),
                ) {
                    let path = Path::new(path);
                    if is_object_id(id) {
                        if unresolvable(validate_object_reference(store, id, path), mode)? {
                            record.objects.insert(id.into());
                        }
                    } else if path_under_objects(store, path) {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("closure contains malformed object id {id:?}"),
                        ));
                    }
                }
                for value in values.values() {
                    walk(store, value, record, mode)?;
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    walk(store, body, record, mode)
}

/// Apply an import mode to one reference's validation result.  Returns
/// whether the reference may be recorded.
pub(super) fn unresolvable(result: io::Result<()>, mode: ImportMode) -> io::Result<bool> {
    match result {
        Ok(()) => Ok(true),
        Err(error) => match mode {
            ImportMode::Strict => Err(error),
            ImportMode::DropUnresolvable => {
                // Nothing for the user to do: the reference protects nothing
                // in this store, and this same sync records the references
                // the store does hold.
                ui::note(&format!(
                    "dropping a historical closure reference this store cannot resolve \
                     ({error}); this sync records the ones the store does hold"
                ));
                Ok(false)
            }
        },
    }
}

pub(super) fn import_absolute_reference(
    store: &Store,
    path: &Path,
    record: &mut RootRecord,
    mode: ImportMode,
) -> io::Result<()> {
    if !path.is_absolute() {
        return Ok(());
    }
    let components: Vec<_> = path.components().collect();
    for window in components.windows(2) {
        let (std::path::Component::Normal(objects), std::path::Component::Normal(id)) =
            (window[0], window[1])
        else {
            continue;
        };
        if objects == "objects" {
            let Some(id) = id.to_str() else {
                continue;
            };
            let root = store.object_path(id);
            if is_object_id(id) && path != root {
                // Inside one of this store's own objects is a different
                // mistake from another store's path: say which (#164).
                // A historical closure may name a file inside an object
                // (an interpreter's path): it protected that object then,
                // so the import keeps the object it points into rather
                // than dropping the reference (#355).
                // A path that climbs with `..` names no one object: it is
                // refused in its own words and never kept.
                let traversal = components.contains(&std::path::Component::ParentDir);
                let inside = !traversal && path.starts_with(&root);
                if inside && mode == ImportMode::DropUnresolvable {
                    if unresolvable(validate_object_reference(store, id, &root), mode)? {
                        record.objects.insert(id.into());
                    }
                    return Ok(());
                }
                let message = if traversal {
                    format!("closure object reference {path:?} contains parent-directory traversal")
                } else if inside {
                    format!(
                        "closure object reference {path:?} is inside object {id}, not \
                         an object root or a projection"
                    )
                } else {
                    format!("closure object reference {path:?} belongs to another store")
                };
                let refused = Err(io::Error::new(io::ErrorKind::InvalidData, message));
                unresolvable(refused, mode)?;
                return Ok(());
            }
        }
    }
    if path_under_objects(store, path) {
        let relative = path.strip_prefix(store.root.join("objects")).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "object path is outside the store",
            )
        })?;
        let mut components = relative.components();
        let Some(std::path::Component::Normal(name)) = components.next() else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "object path has no object id",
            ));
        };
        if components.next().is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "object reference must name an object root",
            ));
        }
        let id = name
            .to_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "object id is not UTF-8"))?;
        if !is_object_id(id) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("closure contains malformed object id {id:?}"),
            ));
        }
        if unresolvable(validate_object_reference(store, id, path), mode)? {
            record.objects.insert(id.into());
        }
        return Ok(());
    }
    if let Some(reference) = projection_reference_for_path(store, path)? {
        record.projections.insert(reference);
    }
    Ok(())
}

pub(super) fn validate_object_reference(store: &Store, id: &str, path: &Path) -> io::Result<()> {
    if !is_object_id(id) || path != store.object_path(id) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("closure object reference {path:?} does not belong to object {id}"),
        ));
    }
    let object = fs::symlink_metadata(path).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("closure object reference {id} is unavailable: {error}"),
        )
    })?;
    if object.file_type().is_symlink() || !object.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("closure object reference {id} is not a real directory"),
        ));
    }
    let metadata = store.root.join("meta").join(format!("{id}.json"));
    let metadata_stat = fs::symlink_metadata(&metadata).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("closure object reference {id} has no metadata: {error}"),
        )
    })?;
    if metadata_stat.file_type().is_symlink() || !metadata_stat.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("closure object reference {id} metadata is not a regular file"),
        ));
    }
    Ok(())
}

pub(super) fn path_under_objects(store: &Store, path: &Path) -> bool {
    path.starts_with(store.root.join("objects"))
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(super) fn install_shipped_ecosystems() {
        crate::tailors::install_kernel_tables();
    }

    /// Every shipped tailor's closure is imported, and a name no tailor
    /// writes is refused.
    #[test]
    fn a_closure_of_every_registered_ecosystem_is_imported() {
        let path = Path::new(".tog/closures/x.json");
        let envelope =
            |name: &str| serde_json::json!({"schema": "closure/1", "ecosystem": name, "body": {}});
        for tailor in crate::tailors::registry() {
            assert!(
                validate_closure_envelope(&envelope(tailor.id()), path).is_ok(),
                "{}",
                tailor.id()
            );
        }
        for name in ["zig", "", "rust"] {
            let error = validate_closure_envelope(&envelope(name), path).unwrap_err();
            assert!(
                error.to_string().contains("unknown closure ecosystem"),
                "{error}"
            );
        }
    }
}

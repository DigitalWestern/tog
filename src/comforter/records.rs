//! The closure records a project committed under `.tog/closures`, read as
//! they are: the envelope, its body, and the exceptions it carries. Nothing
//! here judges freshness, which asks the tailors (`commands::inspect`).

use crate::kernel::fsroot::ProjectRoot;
use crate::kernel::policy::{self, Exception, OptionalGroupSkipped};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::io;
use std::path::{Path, PathBuf};

/// One `.tog/closures/<ecosystem>.json`, envelope fields lifted out.
#[derive(Debug, Clone)]
pub struct ClosureFile {
    pub ecosystem: String,
    pub platform: Option<String>,
    pub projected_at: Option<u64>,
    pub body: Value,
    /// The complete envelope as parsed from the one file read, unknown
    /// fields included: what a signature covers, and what `audit` verifies
    /// before it trusts any field lifted above.
    pub envelope: Value,
    /// Where the envelope was read from.
    pub path: PathBuf,
    /// sha256 of the envelope bytes as read: names the exact record an
    /// audit verdict was computed over.
    pub record_sha256: String,
}

/// Every closure record in `project`, in directory order: the listing and
/// every record are read through its descriptor, tog state read strictly
/// (a symlinked record is refused, never followed). Foreign-platform
/// closures are included (the caller decides what they mean), unlike
/// [`super::read_closure`], which refuses them.
pub fn closure_files(project: &ProjectRoot) -> io::Result<Vec<ClosureFile>> {
    let mut out = Vec::new();
    let dir = Path::new(".tog/closures");
    let Some(names) = project.read_dir(dir)? else {
        return Ok(out);
    };
    for name in names {
        if closure_stem(&name.to_string_lossy()).is_none() {
            continue;
        }
        let text = name.to_str().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "invalid UTF-8 closure filename in {}",
                    project.path().join(dir).display()
                ),
            )
        })?;
        let relative = dir.join(&name);
        let Some(bytes) = project.read_file(&relative)? else {
            continue;
        };
        out.push(closure_file(text, project.path().join(&relative), &bytes)?);
    }
    Ok(out)
}

/// The project in `dir`, held for one report command: `None` when it is
/// absent or not a directory (nothing to report), as detection reads it.
pub fn open_project(dir: &Path) -> io::Result<Option<ProjectRoot>> {
    match ProjectRoot::open(dir) {
        Ok(project) => Ok(Some(project)),
        Err(error)
            if error.kind() == io::ErrorKind::NotFound
                || error.kind() == io::ErrorKind::InvalidData =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

/// The ecosystem stem of a closure file name: `<stem>.json`, not hidden,
/// and not a retired record (`store::RETIRED_CLOSURES`), so a leftover never
/// reads as an orphaned or unknown closure in listing, status, or audit.
fn closure_stem(name: &str) -> Option<&str> {
    name.strip_suffix(".json").filter(|stem| {
        !stem.starts_with('.') && !crate::kernel::store::RETIRED_CLOSURES.contains(stem)
    })
}

fn closure_file(name: &str, path: PathBuf, bytes: &[u8]) -> io::Result<ClosureFile> {
    let stem = closure_stem(name).expect("caller filtered closure names");
    let value: Value = serde_json::from_slice(bytes).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{:?}: {error}; run 'tog'", path.to_string_lossy()),
        )
    })?;
    Ok(ClosureFile {
        ecosystem: value["ecosystem"].as_str().unwrap_or(stem).to_string(),
        platform: value["platform"].as_str().map(str::to_string),
        projected_at: value["projected_at"].as_u64(),
        body: value["body"].clone(),
        envelope: value,
        path,
        record_sha256: hex::encode(Sha256::digest(bytes)),
    })
}

/// The recorded exceptions, or `None` when the closure carries no exception
/// record at all (absence is not evidence of a clean sync).
pub fn recorded_exceptions(closure: &ClosureFile) -> io::Result<Option<Vec<Exception>>> {
    match closure.body.get("exceptions") {
        None | Some(Value::Null) => Ok(None),
        Some(value) => serde_json::from_value(value.clone())
            .map(Some)
            .map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "{:?}: malformed exception record: {error}; run 'tog'",
                        closure.path.to_string_lossy()
                    ),
                )
            }),
    }
}

/// The optional groups the sync left out because nobody requested them
/// (`optional_groups_skipped`, #71). Informational: absence means none,
/// or a closure written before the list existed.
pub fn optional_groups_skipped(closure: &ClosureFile) -> io::Result<Vec<OptionalGroupSkipped>> {
    match closure.body.get("optional_groups_skipped") {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(value) => serde_json::from_value(value.clone()).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "{:?}: malformed optional_groups_skipped: {error}; run 'tog'",
                    closure.path.to_string_lossy()
                ),
            )
        }),
    }
}

/// The exceptions of the resolution record the closure joined, or none. A
/// `resolution` field that is not a record object, or whose exception list
/// does not parse, is refused like a malformed exception record.
pub fn resolution_exceptions(closure: &ClosureFile) -> io::Result<Vec<Exception>> {
    let malformed = |what: String| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{:?}: malformed resolution record: {what}; run 'tog'",
                closure.path.to_string_lossy()
            ),
        )
    };
    let Some(resolution) = closure.body.get("resolution") else {
        return Ok(Vec::new());
    };
    let Some(record) = resolution.as_object() else {
        return Err(malformed("not a JSON object".into()));
    };
    match record.get("exceptions") {
        None => Err(malformed("no exception list".into())),
        Some(list) => {
            serde_json::from_value(list.clone()).map_err(|error| malformed(error.to_string()))
        }
    }
}

/// What `exceptions` found in one closure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExceptionList {
    /// Whether the closure carries an exception record at all
    /// (`body.exceptions`). Absence is not evidence of a clean sync:
    /// `audit` calls such a record outdated, whatever the joined
    /// resolution record says.
    pub recorded: bool,
    /// The recorded list, then whatever the joined resolution record adds
    /// that the list does not already name, each kind spelled the one way
    /// this binary judges and prints (`policy::canonical_kind`).
    pub exceptions: Vec<Exception>,
}

/// Every exception the closure carries, from both places it can record one.
/// Both are read even when the top-level list is absent, so a malformed
/// resolution record is refused the same way whichever list is missing,
/// and `status` still shows what the joined record says.
pub fn exceptions(closure: &ClosureFile) -> io::Result<ExceptionList> {
    let recorded = recorded_exceptions(closure)?;
    let joined = resolution_exceptions(closure)?;
    let canonical = |mut exception: Exception| {
        exception.kind = policy::canonical_kind(&exception.kind).to_string();
        exception
    };
    let mut exceptions: Vec<Exception> = recorded
        .clone()
        .unwrap_or_default()
        .into_iter()
        .map(canonical)
        .collect();
    for exception in joined.into_iter().map(canonical) {
        if !exceptions.contains(&exception) {
            exceptions.push(exception);
        }
    }
    Ok(ExceptionList {
        recorded: recorded.is_some(),
        exceptions,
    })
}

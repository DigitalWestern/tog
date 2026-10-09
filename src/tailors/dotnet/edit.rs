//! `tog add` / `remove` / `update` for .NET (`Tailor::edit_manifest`). It
//! refuses: tog never evaluates MSBuild outside the sandbox, and `dotnet
//! add package` restores, so the user runs the edit with their own SDK.

use crate::tailors::edit::{
    by_hand, registry_latest, EditOutcome, EditVerb, ManifestEdit, PackageRegistry,
};
use std::io;

/// How `tog add` names this ecosystem's public registry.
pub(crate) const REGISTRY: PackageRegistry = PackageRegistry {
    prefix: "nuget",
    name: "NuGet",
};

/// `Tailor::registry_exists`: `Some(latest version)` when NuGet knows
/// `name`.
pub(crate) fn registry_exists(name: &str) -> io::Result<Option<String>> {
    let lower = name.to_ascii_lowercase();
    let url = format!("https://api.nuget.org/v3-flatcontainer/{lower}/index.json");
    registry_latest(REGISTRY, name, &url, |v| {
        v["versions"]
            .as_array()
            .and_then(|versions| versions.last())
            .and_then(|version| version.as_str())
            .map(str::to_string)
    })
}

/// A dotted name whose every part starts upper-case (`Newtonsoft.Json`) is
/// NuGet's; PyPI's dotted names are lower-case.
pub(crate) fn claims_package_name(name: &str) -> bool {
    name.contains('.')
        && name
            .split('.')
            .all(|part| part.chars().next().is_some_and(|c| c.is_ascii_uppercase()))
}

/// `Tailor::edit_manifest` for .NET: the refusal naming the commands to run.
pub(crate) fn edit_manifest(edit: &ManifestEdit<'_>) -> io::Result<EditOutcome> {
    let names = edit.texts().join(" ");
    Err(by_hand(match edit.verb {
        EditVerb::Add => format!(
            "tog never evaluates MSBuild outside the sandbox, and 'dotnet add package' restores: run 'dotnet add package {names}' then 'dotnet restore --force-evaluate' with your own SDK, commit packages.lock.json, then 'tog'"
        ),
        EditVerb::Remove => format!(
            "run 'dotnet remove package {names}' then 'dotnet restore --force-evaluate' with your own SDK, commit packages.lock.json, then 'tog'"
        ),
        EditVerb::Update => "edit the PackageReference versions, run 'dotnet restore --force-evaluate' with your own SDK, commit packages.lock.json, then 'tog'".to_string(),
    }))
}

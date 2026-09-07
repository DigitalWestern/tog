//! `blanket x <tool>`: run a tool from a registry without adding it to the
//! project, cached forever (CLI.md 2.4). A synthetic single-requirement
//! plan goes through the ordinary realize path, so the environment is an
//! input-addressed store object; the second run is a store hit. Each tool
//! gets a tiny project directory under `~/.blanket/x/` holding the
//! projection and its closure, which registers it as a gc root like any
//! other project.

use std::fs;
use std::io;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha224, Sha256};

use crate::platform::Platform;
use crate::store::Store;
use crate::{fetch, inspect, npm, policy, project, pypi, pyselect, python, ui};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// `python` or `node`, when the spelling or a flag decided it.
    pub ecosystem: Option<String>,
    /// The package providing the tool, when its name differs.
    pub from: Option<String>,
    /// `tool` or `tool@version`.
    pub tool: String,
    pub args: Vec<String>,
}

fn other(message: impl Into<String>) -> io::Error {
    io::Error::other(message.into())
}

/// `ruff@0.6.1` → (`ruff`, Some(`0.6.1`)); `@scope/cli@2` keeps its scope.
pub fn split_version(text: &str) -> (&str, Option<&str>) {
    match text.rfind('@') {
        Some(0) | None => (text, None),
        Some(index) => (&text[..index], Some(&text[index + 1..])),
    }
}

/// The executable name a package installs, by convention: the package
/// name without an npm scope.
fn default_bin(package: &str) -> &str {
    package.rsplit_once('/').map_or(package, |(_, name)| name)
}

fn safe(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || "._-".contains(c) {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn home() -> io::Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| other("HOME is not set"))
}

fn choose_ecosystem(request: &Request, cwd: &Path) -> io::Result<&'static str> {
    if request.ecosystem.is_some() {
        return choose_from_project(request, &[]);
    }
    for dir in cwd.ancestors() {
        let present = inspect::detected(dir)?;
        if !present.is_empty() {
            return choose_from_project(request, &present);
        }
        // An existing blanket metadata directory is an explicit project
        // boundary, even when the project currently has no manifest. This
        // prevents an unrelated package in an outer checkout from deciding
        // `x`'s registry.
        if dir.join(".blanket").is_dir() {
            break;
        }
    }
    Err(other(format!(
        "x: say which registry provides '{}': 'blanket x py:{0}' (PyPI) or 'blanket x npm:{0}' (npm)",
        request.tool
    )))
}

fn choose_from_project(request: &Request, present: &[&str]) -> io::Result<&'static str> {
    if let Some(name) = request.ecosystem.as_deref() {
        return match name {
            "python" => Ok("python"),
            "node" => Ok("node"),
            other_name => Err(other(format!("x: unsupported ecosystem '{other_name}'"))),
        };
    }
    let python = present.contains(&"python");
    let node = present.contains(&"node");
    match (python, node) {
        (true, true) => Err(other(
            "x: both Python and Node projects are present; choose explicitly with --py or --npm",
        )),
        (true, false) => {
            ui::trace("x: Python, because this project has a Python manifest");
            Ok("python")
        }
        (false, true) => {
            ui::trace("x: npm, because this project has a package.json");
            Ok("node")
        }
        (false, false) => Err(other(format!(
            "x: say which registry provides '{}': 'blanket x py:{0}' (PyPI) or 'blanket x npm:{0}' (npm)",
            request.tool
        ))),
    }
}

fn validate_text(label: &str, value: &str) -> io::Result<()> {
    if value.is_empty()
        || value.bytes().any(|byte| matches!(byte, b'\r' | b'\n' | 0))
        || value.chars().any(char::is_whitespace)
        || value.starts_with('-')
    {
        return Err(other(format!("x: invalid {label} '{value}'")));
    }
    Ok(())
}

fn validate_package(ecosystem: &str, package: &str) -> io::Result<()> {
    validate_text("package", package)?;
    if package.starts_with('/')
        || package.contains('\\')
        || package
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
        || (ecosystem == "python" && package.contains('/'))
    {
        return Err(other(format!("x: invalid package '{package}'")));
    }
    Ok(())
}

fn validate_version(version: &str) -> io::Result<()> {
    validate_text("version", version)
}

/// Whether `version` is the exact release syntax accepted for a delegated
/// package-manager tool: MAJOR.MINOR.PATCH with an optional prerelease.
/// Build metadata is deliberately excluded because Corepack's hash suffix is
/// handled separately by the package-manager field parser.
pub(crate) fn is_exact_version(version: &str) -> bool {
    fn decimal_component(value: &str) -> bool {
        !value.is_empty()
            && (value.len() == 1 || !value.starts_with('0'))
            && value.bytes().all(|byte| byte.is_ascii_digit())
    }

    let (release, prerelease) = version
        .split_once('-')
        .map_or((version, None), |(a, b)| (a, Some(b)));
    let components: Vec<&str> = release.split('.').collect();
    if components.len() != 3 || !components.iter().all(|part| decimal_component(part)) {
        return false;
    }
    let Some(prerelease) = prerelease else {
        return true;
    };
    !prerelease.is_empty()
        && prerelease.split('.').all(|identifier| {
            !identifier.is_empty()
                && identifier
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && (!identifier.bytes().all(|byte| byte.is_ascii_digit())
                    || (identifier.len() == 1 && identifier != "0")
                    || !identifier.starts_with('0'))
        })
}

fn validate_exact_version(version: &str) -> io::Result<()> {
    if !is_exact_version(version) {
        return Err(other(format!(
            "x: node tool version must be an exact MAJOR.MINOR.PATCH release (a prerelease suffix is allowed), found {version:?}"
        )));
    }
    Ok(())
}

fn validate_from_bin(bin: &str) -> io::Result<()> {
    if bin.is_empty()
        || bin == "."
        || bin == ".."
        || !bin
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ".-_".contains(ch))
    {
        return Err(other("x: --from requires a single safe executable name"));
    }
    Ok(())
}

fn canonical_link_target(path: &Path) -> Option<PathBuf> {
    let target = fs::read_link(path).ok()?;
    let target = if target.is_absolute() {
        target
    } else {
        path.parent()?.join(target)
    };
    target.canonicalize().ok()
}

fn encoded_workspace(workspace: &str) -> Option<String> {
    if workspace.is_empty()
        || workspace
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return None;
    }
    Some(workspace.replace('%', "%25").replace('/', "%2F"))
}

fn check_projection_target(
    store: &Store,
    root: &Path,
    ecosystem: &str,
    closure: &serde_json::Value,
    env_path: &Path,
) -> io::Result<()> {
    let missing = || {
        other(format!(
            "x: cached {ecosystem} projection is missing or points elsewhere; run the command again"
        ))
    };
    match ecosystem {
        "python" => {
            if canonical_link_target(&root.join(".venv")) != Some(env_path.to_path_buf()) {
                return Err(missing());
            }
        }
        "node" => {
            if closure["projection_schema"] != "node-forest/2" {
                return Err(missing());
            }
            let projection_id = closure["projection_id"].as_str().ok_or_else(missing)?;
            if projection_id.is_empty() || !projection_id.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(missing());
            }
            let home = store
                .root
                .parent()
                .ok_or_else(|| other("x: cannot locate blanket home for cached projection"))?;
            let project_key = hex::encode(Sha256::digest(
                root.canonicalize()?.to_string_lossy().as_bytes(),
            ));
            let projection = home
                .join("forests")
                .join(&project_key[..32])
                .join(projection_id);
            let expected = projection
                .join("node_modules")
                .canonicalize()
                .map_err(|_| missing())?;
            if canonical_link_target(&root.join("node_modules")) != Some(expected) {
                return Err(missing());
            }
            if let Some(workspaces) = closure["workspaces"].as_array() {
                for workspace in workspaces {
                    let source = workspace.as_str().ok_or_else(missing)?;
                    let encoded = encoded_workspace(source).ok_or_else(missing)?;
                    let expected = projection
                        .join("workspaces")
                        .join(encoded)
                        .join("node_modules")
                        .canonicalize()
                        .map_err(|_| missing())?;
                    if canonical_link_target(&root.join(source).join("node_modules"))
                        != Some(expected)
                    {
                        return Err(missing());
                    }
                }
            }
        }
        _ => {}
    }
    Ok(())
}

/// A cached `x` projection bypasses the normal realization functions. Check
/// both the persisted closure and the store metadata before executing it, so
/// a stricter policy cannot be bypassed by a previously realized tool.
fn check_cached_projection(store: &Store, root: &Path, ecosystem: &str) -> io::Result<()> {
    let closure = project::read_closure(root, ecosystem)?;
    let path_text = closure["env_object"].as_str().ok_or_else(|| {
        other("x: cached closure has no environment object; run the command again")
    })?;
    let path = Path::new(path_text);
    let id = path
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|id| {
            !id.is_empty()
                && id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        })
        .ok_or_else(|| other("x: cached closure has a malformed environment object"))?;
    if path != store.object_path(id) || !store.has(id) {
        return Err(other(
            "x: cached environment object is missing or outside the active store; run the command again",
        ));
    }
    let env_path = path
        .canonicalize()
        .map_err(|_| other("x: cached environment object is unavailable"))?;
    check_projection_target(store, root, ecosystem, &closure, &env_path)?;
    policy::check_cached(store, id)?;

    let persisted: Vec<policy::Exception> = if closure["exceptions"].is_null() {
        Vec::new()
    } else {
        serde_json::from_value(closure["exceptions"].clone())
            .map_err(|error| other(format!("x: invalid cached closure exceptions: {error}")))?
    };
    policy::check_exception_set(id, &persisted)?;
    let object_exceptions = store.exceptions(id)?;
    for exception in persisted {
        if !object_exceptions.contains(&exception) {
            policy::record(&exception.kind, &exception.subject, &exception.detail)?;
        }
    }
    Ok(())
}

pub fn run(platform: Platform, cwd: &Path, request: Request) -> io::Result<()> {
    let ecosystem = choose_ecosystem(&request, cwd)?;
    let (tool, tool_version) = split_version(&request.tool);
    let (package, from_version) = request.from.as_deref().map_or((tool, None), split_version);
    validate_package(ecosystem, package)?;
    if let Some(version) = tool_version {
        validate_version(version)?;
    }
    if let Some(version) = from_version {
        validate_version(version)?;
    }
    let version = match (from_version, tool_version) {
        (Some(from), Some(tool)) if from != tool => {
            return Err(other(
                "x: --from package version conflicts with the tool version; specify only one or use the same version",
            ));
        }
        (Some(from), _) => Some(from),
        (_, tool) => tool,
    };
    let bin = if request.from.is_some() {
        validate_from_bin(tool)?;
        tool
    } else {
        default_bin(tool)
    };
    if tool.is_empty() || package.is_empty() {
        return Err(other("x: empty tool name"));
    }
    let store = Store::open()?;
    let root = if ecosystem == "node" {
        node_cache_root(&store, platform, package, version)?
    } else {
        let key = hex::encode(Sha256::digest(
            format!(
                "x/2\0{}\0{ecosystem}\0{package}\0{}\0{}",
                store.root.display(),
                version.unwrap_or(""),
                platform.triple()
            )
            .as_bytes(),
        ));
        home()?
            .join(".blanket/x")
            .join(format!("py-{}-{}", safe(package), &key[..16]))
    };
    let (executable, path_prefix, env): (PathBuf, Vec<PathBuf>, Vec<(String, PathBuf)>) =
        match ecosystem {
            "python" => {
                let venv = root.join(".venv");
                let executable = venv.join("bin").join(bin);
                if !executable.is_file() {
                    realize_python(&store, platform, &root, package, version)?;
                } else {
                    check_cached_projection(&store, &root, "python")?;
                }
                if !executable.is_file() {
                    return Err(other(format!(
                        "'{package}' installed but provides no '{bin}' executable; name it with --from: 'blanket x --from {package} <tool>'"
                    )));
                }
                (
                    executable,
                    vec![venv.join("bin")],
                    vec![("VIRTUAL_ENV".to_string(), venv)],
                )
            }
            _ => {
                let node_modules = root.join("node_modules");
                let executable = node_modules.join(".bin").join(bin);
                if !executable.is_file() {
                    realize_node(&store, platform, &root, package, version)?;
                } else {
                    check_cached_projection(&store, &root, "node")?;
                }
                if !executable.is_file() {
                    return Err(other(format!(
                        "'{package}' installed but provides no '{bin}' executable; name it with --from: 'blanket x --from {package} <tool>'"
                    )));
                }
                let node_obj = npm::ensure_node_for(&store, platform)?;
                (
                    executable,
                    vec![node_modules.join(".bin"), node_obj.join("bin")],
                    Vec::new(),
                )
            }
        };
    let mut path: Vec<String> = path_prefix
        .iter()
        .map(|dir| dir.to_string_lossy().into_owned())
        .collect();
    path.push(std::env::var("PATH").unwrap_or_default());
    let mut command = Command::new(&executable);
    command.args(&request.args).env("PATH", path.join(":"));
    for (key, value) in env {
        command.env(key, value);
    }
    if ecosystem == "python" {
        command.env("PYTHONDONTWRITEBYTECODE", "1");
    }
    ui::trace_command(&command);
    Err(command.exec())
}

fn node_cache_root(
    store: &Store,
    platform: Platform,
    package: &str,
    version: Option<&str>,
) -> io::Result<PathBuf> {
    let key = hex::encode(Sha256::digest(
        format!(
            "x/2\0{}\0node\0{package}\0{}\0{}",
            store.root.display(),
            version.unwrap_or(""),
            platform.triple()
        )
        .as_bytes(),
    ));
    Ok(home()?
        .join(".blanket/x")
        .join(format!("npm-{}-{}", safe(package), &key[..16])))
}

/// Realize a Node package whose executable is needed by another delegate.
/// This is the same registered `~/.blanket/x/` environment used by
/// `blanket x`, so a delegate's second invocation is a normal cache hit.
pub(crate) fn realize_node_tool(
    store: &Store,
    platform: Platform,
    package: &str,
    version: &str,
    corepack_sha224: Option<&str>,
) -> io::Result<PathBuf> {
    validate_exact_version(version)?;
    let root = node_cache_root(store, platform, package, Some(version))?;
    let executable = root.join("node_modules/.bin").join(default_bin(package));
    if executable.is_file() {
        check_cached_projection(store, &root, "node")?;
        if let Some(expected) = corepack_sha224 {
            verify_corepack_sha224(store, &root, package, version, expected)?;
        }
        return Ok(root);
    }
    realize_node(store, platform, &root, package, Some(version))?;
    if !executable.is_file() {
        return Err(other(format!(
            "'{package}@{version}' installed but provides no '{package}' executable"
        )));
    }
    if let Some(expected) = corepack_sha224 {
        verify_corepack_sha224(store, &root, package, version, expected)?;
    }
    Ok(root)
}

fn verify_corepack_sha224(
    store: &Store,
    root: &Path,
    package: &str,
    version: &str,
    expected: &str,
) -> io::Result<()> {
    if expected.len() != 56 || !expected.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(other(format!(
            "x: packageManager has a malformed sha224 hash for {package}@{version}"
        )));
    }
    let closure = project::read_closure(root, "node")?;
    let packages = closure["packages"].as_array().ok_or_else(|| {
        other(format!(
            "x: cannot verify packageManager sha224 for {package}@{version}: realized node closure has no package list; hash verification is not supported yet; remove the suffix or use a pnpm package whose tarball is in the verified cache"
        ))
    })?;
    let pnpm = packages.iter().find(|entry| {
        entry["path"].as_str() == Some("node_modules/pnpm")
            && entry["version"].as_str() == Some(version)
    });
    let Some(pnpm) = pnpm else {
        return Err(other(format!(
            "x: cannot verify packageManager sha224 for {package}@{version}: realized node closure has no reachable pnpm artifact; hash verification is not supported yet; remove the suffix or use a pnpm package whose tarball is in the verified cache"
        )));
    };
    let integrity = pnpm["integrity"].as_str().ok_or_else(|| {
        other(format!(
            "x: cannot verify packageManager sha224 for {package}@{version}: pnpm artifact has no integrity and no reachable cache path; hash verification is not supported yet; remove the suffix or use a pnpm package whose tarball is in the verified cache"
        ))
    })?;
    let digest = fetch::Digest::from_sri(integrity).map_err(|error| {
        other(format!(
            "x: cannot verify packageManager sha224 for {package}@{version}: pnpm artifact integrity is invalid ({error}); hash verification is not supported yet; remove the suffix or use a pnpm package whose tarball is in the verified cache"
        ))
    })?;
    let cache_path = store.cache_path(digest.algo(), digest.hex());
    let bytes = fetch::read_cache_verified_digest(store, &digest).map_err(|error| {
        other(format!(
            "x: cannot verify packageManager sha224 for {package}@{version}: verified pnpm artifact cache {} is not reachable ({error}); hash verification is not supported yet; remove the suffix or use a pnpm package whose tarball is in the verified cache",
            cache_path.display()
        ))
    })?;
    let actual = hex::encode(Sha224::digest(bytes));
    if actual != expected.to_ascii_lowercase() {
        return Err(other(format!(
            "x: Corepack sha224 mismatch for {package}@{version}: packageManager declares {expected}, cached pnpm tarball has {actual}; nothing runs"
        )));
    }
    Ok(())
}

fn realize_python(
    store: &Store,
    platform: Platform,
    root: &Path,
    package: &str,
    version: Option<&str>,
) -> io::Result<()> {
    fs::create_dir_all(root)?;
    let selection = pyselect::select_python(platform, &[])?;
    let pin = selection.pin;
    let spec = match version {
        Some(version) => format!("{package}=={version}\n"),
        None => format!("{package}\n"),
    };
    let input = root.join("requirements.in");
    let output = root.join("requirements.txt");
    fs::write(&input, &spec)?;
    ui::note(&format!("resolving {} with the store uv...", spec.trim()));
    let uv = python::ensure_uv_for(store, platform)?.join("uv");
    let mut command = Command::new(uv);
    command
        .args(["pip", "compile"])
        .arg(&input)
        .arg("--generate-hashes");
    if !ui::verbose() {
        command.arg("--quiet");
    }
    command
        .args(["--python-version", pin.version])
        .args(["--index-url", "https://pypi.org/simple"])
        .arg("-o")
        .arg(&output)
        .current_dir(root)
        .env_remove("UV_INDEX_URL")
        .env_remove("UV_DEFAULT_INDEX")
        .env_remove("UV_EXTRA_INDEX_URL")
        .env_remove("PIP_INDEX_URL")
        .env_remove("PIP_EXTRA_INDEX_URL")
        .env_remove("PIP_TRUSTED_HOST")
        .env_remove("PIP_FIND_LINKS");
    ui::trace_command(&command);
    let status = command.status()?;
    if !status.success() {
        return Err(other(format!(
            "could not resolve '{}' from PyPI (uv pip compile exit {status})",
            spec.trim()
        )));
    }
    let text = fs::read_to_string(&output)?;
    let plan = pypi::plan_python(platform, &text, pin.version)?;
    let env = project::realize_env(store, platform, &plan)?;
    project::project_env_with_selection(root, &env, &plan, &selection)?;
    ui::synced(&format!("x {package}"), &env);
    Ok(())
}

fn realize_node(
    store: &Store,
    platform: Platform,
    root: &Path,
    package: &str,
    version: Option<&str>,
) -> io::Result<()> {
    fs::create_dir_all(root)?;
    let manifest = serde_json::json!({
        "name": "blanket-x",
        "private": true,
        "dependencies": { package: version.unwrap_or("latest") },
    });
    fs::write(
        root.join("package.json"),
        serde_json::to_vec_pretty(&manifest)?,
    )?;
    let lock = root.join("package-lock.json");
    if lock.exists() {
        fs::remove_file(&lock)?;
    }
    ui::note(&format!(
        "resolving {package}@{} with the store npm...",
        version.unwrap_or("latest")
    ));
    let node_obj = npm::ensure_node_for(store, platform)?;
    let mut command = Command::new(node_obj.join("bin/npm"));
    command.args(["install", "--package-lock-only", "--ignore-scripts"]);
    if !ui::verbose() {
        command.arg("--silent");
    }
    command.current_dir(root).env(
        "PATH",
        format!(
            "{}:{}",
            node_obj.join("bin").display(),
            std::env::var("PATH").unwrap_or_default()
        ),
    );
    ui::trace_command(&command);
    let status = command.status()?;
    if !status.success() {
        return Err(other(format!(
            "could not resolve '{package}' from npm (npm exit {status})"
        )));
    }
    let plan = npm::plan_npm(platform, &fs::read_to_string(&lock)?)?;
    let env = npm::realize_node_env(store, platform, &plan, &[])?;
    npm::project_node_env(root, &env, platform, &plan, &[], false)?;
    ui::synced(&format!("x {package}"), &env);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_and_bins() {
        assert_eq!(split_version("ruff"), ("ruff", None));
        assert_eq!(split_version("ruff@0.6.1"), ("ruff", Some("0.6.1")));
        assert_eq!(split_version("@angular/cli"), ("@angular/cli", None));
        assert_eq!(
            split_version("@angular/cli@18"),
            ("@angular/cli", Some("18"))
        );
        assert_eq!(default_bin("@angular/cli"), "cli");
        assert_eq!(default_bin("prettier"), "prettier");
        assert_eq!(safe("@angular/cli"), "_angular_cli");
    }

    #[test]
    fn ecosystem_from_spelling_or_project() {
        let request = |eco: Option<&str>| Request {
            ecosystem: eco.map(str::to_string),
            from: None,
            tool: "ruff".into(),
            args: vec![],
        };
        assert_eq!(
            choose_from_project(&request(Some("python")), &[]).unwrap(),
            "python"
        );
        let error = choose_from_project(&request(None), &[]).unwrap_err();
        assert!(error.to_string().contains("blanket x py:ruff"), "{error}");
        assert_eq!(
            choose_from_project(&request(None), &["node"]).unwrap(),
            "node"
        );
        let error = choose_from_project(&request(None), &["python", "node"]).unwrap_err();
        assert!(
            error.to_string().contains("both Python and Node"),
            "{error}"
        );
    }

    #[test]
    fn from_version_is_split_and_conflicts_are_rejected() {
        let (package, version) = split_version("six@1.17.0");
        assert_eq!((package, version), ("six", Some("1.17.0")));
        let error = validate_package("python", "/tmp/tool").unwrap_err();
        assert!(error.to_string().contains("invalid package"), "{error}");
        assert!(validate_from_bin("../tool").is_err());
        assert!(validate_version("1.0\n--index-url evil").is_err());
    }

    #[test]
    fn exact_node_tool_versions_are_full_releases() {
        assert!(is_exact_version("9.1.2"));
        assert!(is_exact_version("9.1.2-rc.1"));
        for version in ["9", "9.x", "^9.1.0", "latest", "9.01.2", "9.1.2+build"] {
            assert!(
                !is_exact_version(version),
                "accepted floating version {version}"
            );
        }
    }
}

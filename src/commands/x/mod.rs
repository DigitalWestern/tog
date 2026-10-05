//! `tog x <tool>`: run a tool from a registry without adding it to the
//! project, cached forever. A synthetic single-requirement plan goes
//! through the ordinary realize path, so the environment is an
//! input-addressed store object; the second run is a store hit. Each tool
//! gets a tiny project directory under `~/.tog/x/` holding the
//! projection and its closure, which registers it as a gc root like any
//! other project.

use std::ffi::{OsStr, OsString};
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::rc::Rc;

use sha2::{Digest, Sha256};

use crate::comforter;
use crate::commands::shared::{registry_tool, registry_tools, CachedTool};
use crate::kernel::activity::StoreActivity;
use crate::kernel::context::Context;
use crate::kernel::platform::Platform;
use crate::kernel::policy;
use crate::kernel::resolve::{DoorKind, ResolutionDoor};
use crate::kernel::store::{self, RootEntry, Store};
use crate::kernel::toolchain::runtime::Selected;
use crate::kernel::ui;

mod cleanup;
mod lock;

pub use cleanup::clean;

use lock::*;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanRequest {
    pub ecosystem: Option<String>,
    pub from: Option<String>,
    pub tool: Option<String>,
}

const X_REQUEST_FILE: &str = ".tog/x.json";
/// [`X_REQUEST_FILE`]'s name inside `.tog`.
const X_REQUEST_NAME: &str = "x.json";
const X_LOCKS_DIR: &str = ".locks";

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
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| other("x: HOME is not set; set HOME to an absolute directory"))?;
    if !home.is_absolute() {
        return Err(other(format!(
            "x: HOME must be an absolute directory, got {}; refusing to use it",
            home.display()
        )));
    }
    Ok(home)
}

/// The toolchain an `x` environment runs on: the project's lock when `x`
/// runs inside one, the shipped selection otherwise. `x` chooses no
/// version of its own and writes no lock.
pub(crate) fn x_toolchain(platform: Platform, cwd: &Path, ecosystem: &str) -> io::Result<Selected> {
    crate::commands::shared::selected_toolchain(platform, cwd, ecosystem)
        .map_err(|error| other(format!("x: {error}")))
}

/// The store object id of the runtime a selection names, from the selected
/// bundle's own row and without touching the store. A shipped pin table
/// could answer by version alone, but the key has to name the object the
/// environment will actually run on, which is the one the selection's
/// digest and recipe identify.
fn runtime_object_id(
    platform: Platform,
    ecosystem: &str,
    toolchain: &Selected,
) -> io::Result<String> {
    registry_tool(ecosystem)?.runtime_object_id(platform, toolchain)
}

/// The helper toolchains an `x` environment of `ecosystem` builds with
/// (`RegistryTool::helpers`), decided as `sync` decides them for the
/// project `x` runs in, and each one's runtime object id for the key.
fn x_helpers(
    platform: Platform,
    cwd: &Path,
    ecosystem: &str,
) -> io::Result<(
    std::collections::BTreeMap<String, Selected>,
    Vec<(String, String)>,
)> {
    let tool = registry_tool(ecosystem)?;
    let helpers =
        crate::commands::shared::selected_helpers(platform, cwd, ecosystem, tool.helpers())
            .map_err(|error| other(format!("x: {error}")))?;
    let ids = helpers
        .iter()
        .map(|(helper, selected)| {
            Ok((
                helper.clone(),
                tool.helper_object_id(platform, helper, selected)?,
            ))
        })
        .collect::<io::Result<Vec<_>>>()?;
    Ok((helpers, ids))
}

/// The name of the directory a cached `x` environment lives in under
/// `~/.tog/x`, for a caller that has to find one without re-deriving the
/// key by hand.
pub fn environment_name(
    store_root: &Path,
    platform: Platform,
    cwd: &Path,
    ecosystem: &str,
    package: &str,
    version: Option<&str>,
) -> io::Result<String> {
    let store = Store::handle(store_root.to_path_buf());
    let toolchain = x_toolchain(platform, cwd, ecosystem)?;
    let runtime_object = runtime_object_id(platform, ecosystem, &toolchain)?;
    let (_, helper_objects) = x_helpers(platform, cwd, ecosystem)?;
    x_root_name(
        &store,
        platform,
        ecosystem,
        package,
        version,
        &toolchain,
        &runtime_object,
        &helper_objects,
    )
}

/// The directory one cached `x` environment lives in.
///
/// The key names the store root because everything else in it is
/// store-independent: two stores must not share one `~/.tog/x/` directory,
/// or the second store's run would find a projection pointing into the
/// first and fail in a way rerunning cannot clear.
///
/// `bundle_id` covers every component version and every platform artifact
/// row, so a changed uv, a changed extraction recipe, or any other bundle
/// component yields a fresh environment; the runtime object id is what the
/// projection actually points at. The name's first word is the registry
/// tool's `cache_prefix`.
///
/// A tool that builds with helper toolchains (npm's node-gyp Python) keys
/// on each helper's runtime object too, under `x/4`: the `x/3` preimage
/// with `<helper>=<object id>` fields appended. A tool with none keys on
/// the `x/3` preimage alone. The key only names the directory: a cache hit
/// also needs the request record (`.tog/x.json`) the run wrote there, so a
/// directory an older tog made without one is rebuilt in place, never
/// reused, and bare `tog x --clean` removes it.
#[allow(clippy::too_many_arguments)]
fn x_root_name(
    store: &Store,
    platform: Platform,
    ecosystem: &str,
    package: &str,
    version: Option<&str>,
    toolchain: &Selected,
    runtime_object: &str,
    helper_objects: &[(String, String)],
) -> io::Result<String> {
    let fields = format!(
        "\0{}\0{ecosystem}\0{package}\0{}\0{}\0{}\0{}\0{runtime_object}",
        store.root.display(),
        version.unwrap_or(""),
        platform.triple(),
        toolchain.primary_version(),
        toolchain.bundle_id()
    );
    let preimage = if helper_objects.is_empty() {
        format!("x/3{fields}")
    } else {
        let mut preimage = format!("x/4{fields}");
        for (helper, object) in helper_objects {
            preimage.push_str(&format!("\0{helper}={object}"));
        }
        preimage
    };
    let key = hex::encode(Sha256::digest(preimage.as_bytes()));
    Ok(format!(
        "{}-{}-{}",
        registry_tool(ecosystem)?.cache_prefix(),
        safe(package),
        &key[..16]
    ))
}

fn ensure_x_metadata_dir(root: &Path) -> io::Result<()> {
    if root
        .file_name()
        .is_some_and(|name| name.as_bytes().first() == Some(&b'.'))
    {
        return Err(other(format!(
            "x: environment root {} may not start with '.'",
            root.display()
        )));
    }
    if let Ok(metadata) = fs::symlink_metadata(root) {
        if metadata.file_type().is_symlink() {
            return Err(other(format!(
                "x: environment root {} is a symlink; refusing to use it",
                root.display()
            )));
        }
    }
    fs::create_dir_all(root)?;
    let metadata_dir = root.join(".tog");
    if let Ok(metadata) = fs::symlink_metadata(&metadata_dir) {
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(other(format!(
                "x: metadata directory {} is not a private directory",
                metadata_dir.display()
            )));
        }
    } else {
        fs::create_dir_all(&metadata_dir)?;
    }
    Ok(())
}

#[cfg(test)]
fn write_x_request(
    root: &Path,
    ecosystem: &str,
    package: &str,
    version: Option<&str>,
    state: &str,
) -> io::Result<()> {
    write_x_request_inner(root, ecosystem, package, version, state, None, None)
}

fn write_x_request_for_store(
    root: &Path,
    store: &Store,
    ecosystem: &str,
    package: &str,
    version: Option<&str>,
    state: &str,
    runtime: Option<(&Selected, &str, &[(String, String)])>,
) -> io::Result<()> {
    write_x_request_inner(
        root,
        ecosystem,
        package,
        version,
        state,
        Some(&store.root),
        runtime,
    )
}

fn write_x_request_inner(
    root: &Path,
    ecosystem: &str,
    package: &str,
    version: Option<&str>,
    state: &str,
    store_root: Option<&Path>,
    runtime: Option<(&Selected, &str, &[(String, String)])>,
) -> io::Result<()> {
    let path = root.join(X_REQUEST_FILE);
    if let Ok(metadata) = fs::symlink_metadata(&path) {
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(other(format!(
                "x: request record {} is not a regular file; refusing to overwrite it",
                path.display()
            )));
        }
    }
    let tmp = root
        .join(".tog")
        .join(format!(".x.json.tmp.{}", std::process::id()));
    let mut record = serde_json::json!({
        "schema": if store_root.is_some() { "x-request/2" } else { "x-request/1" },
        "ecosystem": ecosystem,
        "package": package,
        "version": version,
        "state": state,
    });
    if let Some(store_root) = store_root {
        record["store_root"] = serde_json::Value::String(store_root.display().to_string());
    }
    // What the directory name was computed from, so a reader of the record
    // can tell which runtime this environment belongs to without
    // recomputing the key.
    if let Some((toolchain, runtime_object, helper_objects)) = runtime {
        record["bundle_id"] = serde_json::Value::String(toolchain.bundle_id());
        record["runtime_object"] = serde_json::Value::String(runtime_object.to_string());
        // The helper runtimes the key names (node-gyp's Python), if any.
        if !helper_objects.is_empty() {
            record["helpers"] = serde_json::Value::Object(
                helper_objects
                    .iter()
                    .map(|(helper, object)| {
                        (helper.clone(), serde_json::Value::String(object.clone()))
                    })
                    .collect(),
            );
        }
    }
    fs::write(&tmp, serde_json::to_vec_pretty(&record)?)?;
    fs::rename(tmp, path)
}

fn choose_ecosystem(request: &Request, cwd: &Path) -> io::Result<&'static str> {
    if request.ecosystem.is_some() {
        return choose_from_project(request, &[]);
    }
    if let Some(location) = crate::commands::shared::project_for(cwd)? {
        if !location.detected.is_empty() {
            return choose_from_project(request, &location.detected);
        }
    }
    Err(say_which_registry(&request.tool))
}

/// `x: say which registry provides 'ruff': 'tog x py:ruff' (PyPI) or ...`,
/// one alternative per registry tool.
fn say_which_registry(tool: &str) -> io::Error {
    let choices: Vec<String> = registry_tools()
        .iter()
        .map(|(_, registry)| {
            format!(
                "'tog x {}:{tool}' ({})",
                registry.spelling(),
                registry.registry_name()
            )
        })
        .collect();
    other(format!(
        "x: say which registry provides '{tool}': {}",
        choices.join(" or ")
    ))
}

fn choose_from_project(request: &Request, present: &[&str]) -> io::Result<&'static str> {
    let tools = registry_tools();
    if let Some(name) = request.ecosystem.as_deref() {
        return tools
            .iter()
            .find(|(id, _)| *id == name)
            .map(|(id, _)| *id)
            .ok_or_else(|| other(format!("x: unsupported ecosystem '{name}'")));
    }
    let found: Vec<_> = tools
        .iter()
        .filter(|(id, _)| present.contains(id))
        .collect();
    match found.as_slice() {
        [] => Err(say_which_registry(&request.tool)),
        [(id, registry)] => {
            ui::trace(&format!("x: {}", registry.detection_reason()));
            Ok(id)
        }
        several => {
            let labels: Vec<&str> = several.iter().map(|(_, r)| r.project_label()).collect();
            let flags: Vec<String> = several
                .iter()
                .map(|(_, r)| format!("--{}", r.spelling()))
                .collect();
            Err(other(format!(
                "x: {}{} projects are present; choose explicitly with {}",
                if several.len() == 2 { "both " } else { "" },
                labels.join(" and "),
                flags.join(" or ")
            )))
        }
    }
}

// The `x` argument rules. The parser (`cli/x.rs`) calls these same
// functions, so a bad spelling is a usage error (exit 2) before anything
// runs, and `launch` re-checks what a library caller hands it.

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

/// A package name, spelled as `label` in the message (`tool` when the tool
/// is also the package). One slash is allowed for a scoped npm name, never
/// a path: no leading `/`, no `\\`, no empty, `.` or `..` part.
pub fn validate_package(label: &str, package: &str) -> io::Result<()> {
    validate_text(label, package)?;
    if package.starts_with('/')
        || package.contains('\\')
        || package
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(other(format!("x: invalid {label} '{package}'")));
    }
    Ok(())
}

/// [`validate_package`], and a scoped name only from a registry that has
/// scopes. That half needs the ecosystem, which the parser may not know.
fn validate_package_for(ecosystem: &str, package: &str) -> io::Result<()> {
    validate_package("package", package)?;
    if package.contains('/') && !registry_tool(ecosystem)?.scoped_packages() {
        return Err(other(format!("x: invalid package '{package}'")));
    }
    Ok(())
}

fn validate_version(version: &str) -> io::Result<()> {
    validate_text("version", version)
}

/// The version a request asks for: the tool's (`ruff@0.6.1`) or the
/// `--from` package's, each checked, and refused when both are given and
/// differ.
pub fn request_version<'a>(
    tool_version: Option<&'a str>,
    from_version: Option<&'a str>,
) -> io::Result<Option<&'a str>> {
    for version in [tool_version, from_version].into_iter().flatten() {
        validate_version(version)?;
    }
    match (from_version, tool_version) {
        (Some(from), Some(tool)) if from != tool => Err(other(
            "x: --from package version conflicts with the tool version; specify only one or use the same version",
        )),
        (Some(from), _) => Ok(Some(from)),
        (_, tool) => Ok(tool),
    }
}

pub fn validate_from_bin(bin: &str) -> io::Result<()> {
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

fn check_projection_target(
    store: &Store,
    root: &Path,
    ecosystem: &str,
    closure: &serde_json::Value,
    env_path: &Path,
) -> io::Result<()> {
    if registry_tool(ecosystem)?.projection_points_at(store, root, closure, env_path)? {
        return Ok(());
    }
    Err(other(format!(
        "x: cached {ecosystem} projection is missing or points elsewhere; run the command again"
    )))
}

/// A cached `x` projection bypasses the normal realization functions. Check
/// both the persisted closure and the store metadata before executing it, so
/// a stricter policy cannot be bypassed by a previously realized tool.
fn cached_projection(
    store: &Store,
    activity: &StoreActivity,
    root: &Path,
    ecosystem: &str,
) -> io::Result<(serde_json::Value, String)> {
    let closure = comforter::read_closure(root, ecosystem)?;
    let path_text = closure["env_object"].as_str().ok_or_else(|| {
        other("x: cached closure has no environment object; run the command again")
    })?;
    let path = PathBuf::from(path_text);
    let id = path
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|id| crate::kernel::store::is_object_id(id))
        .map(str::to_owned)
        .ok_or_else(|| {
            other(
                "x: cached closure has a malformed environment object; \
                 run the command again to rebuild it",
            )
        })?;
    if path != store.object_path(&id) || !store.has_with_activity(activity, &id)? {
        return Err(other(
            "x: cached environment object is missing or outside the active store; run the command again",
        ));
    }
    let env_path = path.canonicalize().map_err(|_| {
        other(
            "x: cached environment object is unavailable; \
             run the command again to rebuild it",
        )
    })?;
    check_projection_target(store, root, ecosystem, &closure, &env_path)?;
    Ok((closure, id))
}

fn check_cached_projection(
    store: &Store,
    activity: &StoreActivity,
    root: &Path,
    ecosystem: &str,
) -> io::Result<()> {
    let (closure, id) = cached_projection(store, activity, root, ecosystem)?;
    policy::check_cached_with_activity(store, activity, &id)?;

    let persisted: Vec<policy::Exception> = if closure["exceptions"].is_null() {
        Vec::new()
    } else {
        serde_json::from_value(closure["exceptions"].clone())
            .map_err(|error| other(format!("x: invalid cached closure exceptions: {error}")))?
    };
    policy::check_exception_set(&id, &persisted)?;
    let object_exceptions = store.exceptions(&id)?;
    for exception in persisted {
        if !object_exceptions.contains(&exception) {
            policy::record(&exception.kind, &exception.subject, &exception.detail)?;
        }
    }
    Ok(())
}

#[derive(Debug)]
struct XRecord {
    ecosystem: String,
    package: String,
    version: Option<String>,
    state: Option<String>,
    store_root: Option<PathBuf>,
}

fn read_x_request(root: &Path) -> Option<XRecord> {
    let path = root.join(X_REQUEST_FILE);
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)
        .ok()?;
    parse_x_request(file)
}

/// [`read_x_request`] below a held root directory: `.tog` and the record
/// are each opened without following a symlink, so a rename of the root's
/// pathname cannot make this read another root's record.
fn read_x_request_in(root: &fs::File) -> Option<XRecord> {
    let tog = store::open_directory_at(root.as_raw_fd(), b".tog").ok()?;
    let file = store::open_file_at(
        tog.as_raw_fd(),
        X_REQUEST_NAME.as_bytes(),
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        0,
    )
    .ok()?;
    parse_x_request(file)
}

fn parse_x_request(file: fs::File) -> Option<XRecord> {
    let stat = file.metadata().ok()?;
    if !stat.is_file() {
        return None;
    }
    let value: serde_json::Value = serde_json::from_reader(file).ok()?;
    if !matches!(
        value.get("schema").and_then(serde_json::Value::as_str),
        Some("x-request/1" | "x-request/2")
    ) {
        return None;
    }
    Some(XRecord {
        ecosystem: value.get("ecosystem")?.as_str()?.to_string(),
        package: value.get("package")?.as_str()?.to_string(),
        version: value
            .get("version")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string),
        state: value
            .get("state")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string),
        store_root: value
            .get("store_root")
            .and_then(|value| value.as_str().map(PathBuf::from)),
    })
}

/// Decide whether a cached root can be executed as it stands. A `true` answer
/// means the cached projection has already been fully validated here,
/// including its policy exceptions: callers must not validate it a second
/// time or every persisted exception is narrated and queued twice.
fn x_request_is_ready(
    store: &Store,
    activity: &StoreActivity,
    root: &Path,
    ecosystem: &str,
    executable: &Path,
) -> io::Result<bool> {
    // Only a root whose run recorded it `ready` is complete. A root with no
    // record, an unreadable one, or one still `realizing` is rebuilt.
    if read_x_request(root)
        .and_then(|record| record.state)
        .as_deref()
        != Some("ready")
    {
        return Ok(false);
    }
    if !executable.is_file() || cached_projection(store, activity, root, ecosystem).is_err() {
        return Ok(false);
    }
    // Keep policy failures as failures. They must not be mistaken for a
    // missing projection and bypassed by a fresh realization.
    check_cached_projection(store, activity, root, ecosystem)?;
    Ok(true)
}

/// `tog x`: `x` has its own cached projection path and therefore does
/// not pass through sync's policy initialization. Load the cwd policy,
/// including all applicable ancestors, before realization or any cache-hit
/// checks. The dispatcher recorded `--strict` before this runs, so a
/// strict `x` judges the tool under the policy a strict sync would apply.
pub fn run(ctx: &Context, request: Request) -> io::Result<i32> {
    let cwd = ctx.project_dir();
    policy::init(&cwd)?;
    launch(ctx.platform, &cwd, request, &ctx.activity)
}

pub fn launch(
    platform: Platform,
    cwd: &Path,
    request: Request,
    activity: &StoreActivity,
) -> io::Result<i32> {
    let ecosystem = choose_ecosystem(&request, cwd)?;
    let (tool, tool_version) = split_version(&request.tool);
    let (package, from_version) = request.from.as_deref().map_or((tool, None), split_version);
    validate_package_for(ecosystem, package)?;
    let version = request_version(tool_version, from_version)?;
    let bin = if request.from.is_some() {
        validate_from_bin(tool)?;
        tool
    } else {
        default_bin(tool)
    };
    if tool.is_empty() || package.is_empty() {
        return Err(other("x: empty tool name"));
    }
    let x_home = home()?;
    let store = Store::open()?;
    store.require_activity(activity, "x")?;
    let tool = registry_tool(ecosystem)?;
    let toolchain = x_toolchain(platform, cwd, ecosystem)?;
    let runtime_object = tool.runtime_object_id(platform, &toolchain)?;
    let (helpers, helper_objects) = x_helpers(platform, cwd, ecosystem)?;
    let root = x_home.join(".tog/x").join(x_root_name(
        &store,
        platform,
        ecosystem,
        package,
        version,
        &toolchain,
        &runtime_object,
        &helper_objects,
    )?);
    let _x_lock = acquire_x_root(&root)?;
    let executable = tool.bin_dir(&root).join(bin);
    let mut attribution = policy::Attribution::open(ecosystem)?;
    let ready = x_request_is_ready(&store, activity, &root, ecosystem, &executable)?;
    if !ready {
        write_x_request_for_store(
            &root,
            &store,
            ecosystem,
            package,
            version,
            "realizing",
            Some((
                &toolchain,
                runtime_object.as_str(),
                helper_objects.as_slice(),
            )),
        )?;
        let mut door =
            ResolutionDoor::open(&store, activity, platform, DoorKind::X, &mut attribution)?;
        tool.realize(&mut door, &root, package, version, &toolchain, &helpers)?;
        attribution.finish(true)?;
        write_x_request_for_store(
            &root,
            &store,
            ecosystem,
            package,
            version,
            "ready",
            Some((
                &toolchain,
                runtime_object.as_str(),
                helper_objects.as_slice(),
            )),
        )?;
    } else {
        // `x_request_is_ready` already validated this projection against
        // the store and the active policy. Validating it again would
        // narrate and queue every persisted exception twice.
        attribution.discard();
    }
    if !executable.is_file() {
        return Err(other(format!(
            "'{package}' installed but provides no '{bin}' executable; name it with --from: 'tog x --from {package} <tool>'"
        )));
    }
    let launch_env = tool.launch_env(&store, activity, platform, &root, &toolchain)?;
    let mut path: Vec<String> = launch_env
        .path
        .iter()
        .map(|dir| dir.to_string_lossy().into_owned())
        .collect();
    path.push(std::env::var("PATH").unwrap_or_default());
    let mut command = Command::new(&executable);
    command.args(&request.args).env("PATH", path.join(":"));
    for (key, value) in launch_env.vars {
        command.env(key, value);
    }
    ui::trace_command(&command);
    let status =
        crate::kernel::supervise::child_status(run_installed_tool(&mut command, activity))?;
    Ok(crate::commands::shared::child_status_code(&status))
}

/// Run the executable `tog x` installed, with the user's arguments. The
/// tool is the user's program (`tog x cowsay`, or a package that ships a
/// `cargo` wrapper), not a resolution tog starts, so neither the door nor
/// the host-local tripwire applies to it.
// Reviewed site (tests/architecture.rs): the user's own program, which may be any tool.
#[allow(clippy::disallowed_methods)]
fn run_installed_tool(
    command: &mut Command,
    activity: &StoreActivity,
) -> io::Result<std::process::ExitStatus> {
    crate::kernel::supervise::status(command, activity)
}

/// Realize `package@version` from `ecosystem`'s registry tool for another
/// command (a dependency edit's pinned pnpm), in the same registered
/// `~/.tog/x/` environment `tog x` would use for it from `project`: both
/// key on the same fields, so the two share one environment rather than
/// realizing it twice. The resolver runs through `door`.
pub(crate) fn realize_cached_tool(
    project: &Path,
    ecosystem: &str,
    package: &str,
    version: &str,
    door: &mut ResolutionDoor<'_>,
) -> io::Result<CachedTool> {
    let (store, activity, platform) = (door.store(), door.lease(), door.platform());
    store.require_activity(activity, &format!("{ecosystem} tool"))?;
    let tool = registry_tool(ecosystem)?;
    let toolchain = x_toolchain(platform, project, ecosystem)?;
    let runtime_object = tool.runtime_object_id(platform, &toolchain)?;
    let (helpers, helper_objects) = x_helpers(platform, project, ecosystem)?;
    let root = home()?.join(".tog/x").join(x_root_name(
        store,
        platform,
        ecosystem,
        package,
        Some(version),
        &toolchain,
        &runtime_object,
        &helper_objects,
    )?);
    // Take the same shared lifecycle lock `tog x` takes, and hand it back
    // to the caller. `tog x --clean` removes a cached root under an
    // exclusive lock, so without this a cleanup running alongside a
    // dependency edit could delete the delegate's environment out from under
    // it. The caller holds the lock for as long as it uses the root.
    let lock = acquire_x_root(&root)?;
    let executable = tool.bin_dir(&root).join(default_bin(package));
    // The same request record `tog x` writes, so the environment is one
    // `tog x` reuses and `tog x --clean <tool>` can name, and its
    // originating store is known when it is removed.
    let runtime = Some((
        &toolchain,
        runtime_object.as_str(),
        helper_objects.as_slice(),
    ));
    if cached_tool_hit(
        store,
        activity,
        &root,
        ecosystem,
        package,
        version,
        &executable,
        runtime,
    )? {
        return Ok(CachedTool {
            root,
            lock,
            realized: false,
        });
    }
    tool.realize(door, &root, package, Some(version), &toolchain, &helpers)?;
    if !executable.is_file() {
        return Err(other(format!(
            "'{package}@{version}' installed but provides no '{package}' executable"
        )));
    }
    write_x_request_for_store(
        &root,
        store,
        ecosystem,
        package,
        Some(version),
        "ready",
        runtime,
    )?;
    Ok(CachedTool {
        root,
        lock,
        realized: true,
    })
}

/// The cache decision `realize_cached_tool` makes, under the x-root lock
/// its caller holds: reuse the root exactly when `tog x` would
/// (`x_request_is_ready`: a `ready` request record and a valid projection),
/// otherwise mark it `realizing` and answer `false` so the caller rebuilds
/// it. A root with no record, an unreadable one, or one left `realizing`
/// is never reused, whatever executable it holds.
#[allow(clippy::too_many_arguments)]
fn cached_tool_hit(
    store: &Store,
    activity: &StoreActivity,
    root: &Path,
    ecosystem: &str,
    package: &str,
    version: &str,
    executable: &Path,
    runtime: Option<(&Selected, &str, &[(String, String)])>,
) -> io::Result<bool> {
    if x_request_is_ready(store, activity, root, ecosystem, executable)? {
        return Ok(true);
    }
    write_x_request_for_store(
        root,
        store,
        ecosystem,
        package,
        Some(version),
        "realizing",
        runtime,
    )?;
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::cleanup::*;
    use super::*;
    use crate::kernel::testutil::TempDir;
    use std::sync::mpsc;
    use std::thread;

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

    /// A one-component toolchain selection that no catalog bump moves.
    fn fixed_selection(ecosystem: &str, primary: &str, version: &str) -> Selected {
        use crate::kernel::toolchain::{Bundle, Component, Source};
        Selected {
            helpers: Default::default(),
            ecosystem: ecosystem.into(),
            bundle: Bundle {
                release: format!("{primary}-{version}-r1"),
                revision: Some(1),
                primary: vec![primary.into()],
                components: vec![Component::new(primary, version)],
                artifacts: Vec::new(),
            },
            lock_sha256: None,
            source: Source::Lock,
        }
    }

    /// The cache key follows the runtime. Two environments that differ
    /// only in the bundle they run on, or only in the object that bundle
    /// realizes to, are two directories; everything else about the request
    /// being equal keeps one.
    #[test]
    fn the_x_key_follows_the_runtime() {
        let store = Store::for_test(PathBuf::from("/tmp/tog-x-key-fixture"));
        let platform = Platform::host().unwrap();
        let selected = fixed_selection("python", "cpython", "3.12.14");
        let name = |toolchain: &Selected, runtime_object: &str| {
            x_root_name(
                &store,
                platform,
                "python",
                "ruff",
                Some("0.6.1"),
                toolchain,
                runtime_object,
                &[],
            )
            .unwrap()
        };
        let base = name(&selected, "object-a");
        assert_eq!(base, name(&selected, "object-a"), "the key is not stable");
        assert!(base.starts_with("py-ruff-"), "{base}");

        // A different realized runtime for the same bundle.
        assert_ne!(base, name(&selected, "object-b"));

        // A different bundle: `bundle_id` covers every component and
        // artifact row, so a changed uv or a changed extraction recipe is a
        // different environment even when the runtime object is the same.
        // `release` is provenance and is deliberately not in it.
        let mut renamed = selected.clone();
        renamed.bundle.release = format!("{}-rev2", renamed.bundle.release);
        assert_eq!(selected.bundle_id(), renamed.bundle_id());
        assert_eq!(base, name(&renamed, "object-a"));

        let mut other = selected.clone();
        let component = other.bundle.components.last_mut().unwrap();
        component.version = format!("{}.1", component.version);
        assert_ne!(selected.bundle_id(), other.bundle_id());
        assert_ne!(base, name(&other, "object-a"));
    }

    /// `x` reaches Python and Node only through `Tailor::registry_tool`;
    /// an ecosystem without one is refused in the trait default's words,
    /// and the tools put executables where the cached-root checks look.
    #[test]
    fn registry_tools_come_from_the_tailors() {
        let root = Path::new("/x-root");
        let python = registry_tool("python").unwrap();
        assert_eq!(python.cache_prefix(), "py");
        assert_eq!(python.bin_dir(root), root.join(".venv/bin"));
        let node = registry_tool("node").unwrap();
        assert_eq!(node.cache_prefix(), "npm");
        assert_eq!(node.bin_dir(root), root.join("node_modules/.bin"));
        let error = registry_tool("go").err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        assert_eq!(error.to_string(), "tog x does not support go");
        assert!(registry_tool("cobol").is_err());
    }

    /// The `x/3` and `x/4` cache directory names, byte for byte. A cached
    /// environment is found again only by recomputing this name, so any
    /// change to the key's bytes (its preimage, the hash, or the `py`/`npm`
    /// prefix a registry tool supplies) orphans every cache directory an
    /// earlier tog made. The toolchain is a fixed bundle, not the shipped
    /// catalog, so a catalog bump does not move these goldens.
    ///
    /// `py:` outside a project that locks Rust has no helper and keeps its
    /// `x/3` name; inside one it keys on the locked Rust under `x/4` (#190).
    /// `npm:` keys on its node-gyp Python under `x/4`; the helper-less
    /// spelling of the same request is still the `x/3` golden, so only the
    /// helper moved it.
    #[test]
    fn x_root_names_are_byte_identical_goldens() {
        let store = Store::for_test(PathBuf::from("/home/golden/.tog/store"));
        let platform = Platform::X86_64UnknownLinuxGnu;
        let python = fixed_selection("python", "cpython", "3.12.14");
        let node = fixed_selection("node", "node", "24.20.0");
        assert_eq!(
            x_root_name(
                &store,
                platform,
                "python",
                "ruff",
                Some("0.6.1"),
                &python,
                "cpython-object",
                &[],
            )
            .unwrap(),
            "py-ruff-215b4362097370ce"
        );
        assert_eq!(registry_tool("python").unwrap().helpers(), ["rust"]);
        let py = |rust: &str| {
            x_root_name(
                &store,
                platform,
                "python",
                "ruff",
                Some("0.6.1"),
                &python,
                "cpython-object",
                &[("rust".to_string(), rust.to_string())],
            )
            .unwrap()
        };
        assert_eq!(py("rust-object"), "py-ruff-d22c85ac801414bf");
        assert_ne!(py("other-rust-object"), py("rust-object"));
        assert_eq!(
            x_root_name(
                &store,
                platform,
                "node",
                "@angular/cli",
                None,
                &node,
                "nodejs-object",
                &[],
            )
            .unwrap(),
            "npm-_angular_cli-5dd983d9952f7476"
        );
        assert_eq!(registry_tool("node").unwrap().helpers(), ["python"]);
        let npm = |gyp_python: &str| {
            x_root_name(
                &store,
                platform,
                "node",
                "@angular/cli",
                None,
                &node,
                "nodejs-object",
                &[("python".to_string(), gyp_python.to_string())],
            )
            .unwrap()
        };
        assert_eq!(npm("cpython-object"), "npm-_angular_cli-c9f235c1ffa1b37a");
        assert_ne!(npm("other-cpython-object"), npm("cpython-object"));
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
        assert!(error.to_string().contains("tog x py:ruff"), "{error}");
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

    /// `--from six@1` asks for version 1 of the package while the tool
    /// `six@2` asks for version 2. The parser refuses that pair, but a
    /// `Request` can reach `x` without the parser, so a run and a clean
    /// each refuse it themselves instead of silently picking one version.
    /// Agreeing versions are fine.
    #[test]
    fn a_from_version_that_disagrees_with_the_tool_version_is_refused() {
        let (_store, activity) = crate::kernel::testutil::detached_lease();
        let cwd = TempDir::named("x-conflict");
        let error = launch(
            Platform::host().unwrap(),
            &cwd.0,
            Request {
                ecosystem: Some("python".into()),
                from: Some("six@1".into()),
                tool: "six@2".into(),
                args: vec![],
            },
            &activity,
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("--from package version conflicts with the tool version"),
            "{error}"
        );

        let clean = |from: &str, tool: &str| {
            clean_filter(CleanRequest {
                ecosystem: Some("python".into()),
                from: Some(from.into()),
                tool: Some(tool.into()),
            })
        };
        let error = clean("six@1", "six@2").unwrap_err();
        assert!(
            error
                .to_string()
                .contains("--from package version conflicts with the tool version"),
            "{error}"
        );
        let agreed = clean("six@1", "six@1").unwrap();
        assert_eq!(agreed.package.as_deref(), Some("six"));
        assert_eq!(agreed.version.as_deref(), Some("1"));
    }

    #[test]
    fn package_bin_and_version_inputs_are_validated() {
        let error = validate_package_for("python", "/tmp/tool").unwrap_err();
        assert!(error.to_string().contains("invalid package"), "{error}");
        assert!(validate_from_bin("../tool").is_err());
        assert!(validate_version("1.0\n--index-url evil").is_err());
    }

    /// An npm tool run inside a project builds its native addons on the
    /// Python a sync of that project would give node-gyp: the project's own
    /// (3.13 here) when it has Python, the shipped default otherwise. The
    /// helper's object is in the key, so the two never share a cache
    /// directory, and a `py:` tool's name does not depend on it.
    #[test]
    fn an_npm_tool_keys_on_the_projects_gyp_python() {
        let platform = Platform::host().unwrap();
        let temp = TempDir::named("x-gyp");
        let base = &temp.0;
        let store_root = base.join("store");
        let locks_python = base.join("locks-python");
        let node_only = base.join("node-only");
        for (project, python) in [(&locks_python, true), (&node_only, false)] {
            fs::create_dir_all(project.join(".tog")).unwrap();
            fs::write(project.join("package.json"), "{}\n").unwrap();
            if python {
                fs::write(project.join("requirements.txt"), "six==1.17.0\n").unwrap();
                fs::write(project.join(".python-version"), "3.13\n").unwrap();
            }
        }

        let (helpers, ids) = x_helpers(platform, &locks_python, "node").unwrap();
        assert!(helpers["python"]
            .version("cpython")
            .unwrap()
            .starts_with("3.13."));
        assert_eq!(ids.len(), 1);
        assert!(ids[0].1.contains("-cpython-3.13."), "{ids:?}");
        let (helpers, ids) = x_helpers(platform, &node_only, "node").unwrap();
        let shipped = crate::tailors::node::shipped_gyp_python().unwrap();
        assert_eq!(helpers["python"].bundle_id(), shipped.bundle_id());
        assert_eq!(
            ids[0].1,
            crate::kernel::provider::cpython::cpython_object_id(&shipped, platform).unwrap()
        );
        let (helpers, ids) = x_helpers(platform, &locks_python, "python").unwrap();
        assert!(helpers.is_empty() && ids.is_empty());

        let name = |project: &Path, ecosystem: &str, package: &str| {
            environment_name(&store_root, platform, project, ecosystem, package, None).unwrap()
        };
        assert_ne!(
            name(&locks_python, "node", "prettier"),
            name(&node_only, "node", "prettier")
        );
    }

    #[test]
    fn shared_x_lock_blocks_nonblocking_cleanup_until_runner_exit() {
        let temp = TempDir::named("x-lock");
        let base = &temp.0;
        let root = base.join("x").join("py-ruff-test");
        fs::create_dir_all(&root).unwrap();
        let shared = lock_x_root(&root, false, false)
            .unwrap()
            .expect("shared lock");
        // SAFETY: fcntl operates on the descriptor owned by `shared`.
        let flags = unsafe { libc::fcntl(shared.as_raw_fd(), libc::F_GETFD) };
        assert!(flags >= 0);
        assert_ne!(flags & libc::FD_CLOEXEC, 0);
        assert!(lock_x_root(&root, true, true).unwrap().is_none());
        drop(shared);
        // `drop` closes this process's descriptor, but a `flock` lives on the
        // open file description, not on the descriptor. Any sibling test that
        // spawns a child forks the whole descriptor table, so between that
        // `fork` and the `exec` that honours `FD_CLOEXEC` the child holds a
        // second reference to this shared lock. The exclusive try-lock below
        // then loses with `EWOULDBLOCK` through no fault of `lock_x_root`.
        // The window is microseconds wide, so retry briefly; the assertion
        // above still proves the lock blocks while `shared` is held.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let exclusive = loop {
            if let Some(file) = lock_x_root(&root, true, true).unwrap() {
                break Some(file);
            }
            if std::time::Instant::now() >= deadline {
                break None;
            }
            thread::sleep(std::time::Duration::from_millis(10));
        };
        assert!(
            exclusive.is_some(),
            "exclusive lock stayed blocked for two seconds after the shared lock was dropped"
        );
        drop(exclusive);
    }

    #[test]
    fn cleanup_lock_waits_for_runner_recreation() {
        let temp = TempDir::named("x-lock-race");
        let base = &temp.0;
        let root = base.join("x").join("py-race-test");
        fs::create_dir_all(&root).unwrap();
        let cleanup = lock_x_root(&root, true, false)
            .unwrap()
            .expect("cleanup lock");
        let (ready_tx, ready_rx) = mpsc::channel();
        let runner_root = root.clone();
        let runner = thread::spawn(move || {
            let shared = acquire_x_root(&runner_root).unwrap();
            ready_tx.send(()).unwrap();
            drop(shared);
        });

        assert!(
            ready_rx
                .recv_timeout(std::time::Duration::from_millis(100))
                .is_err(),
            "runner inspected or recreated the root before acquiring its shared lock"
        );
        fs::remove_dir_all(&root).unwrap();
        drop(cleanup);
        ready_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .expect("runner did not recreate the root after cleanup released its lock");
        runner.join().unwrap();
        assert!(root.join(".tog").is_dir());
    }

    #[test]
    fn fd_relative_removal_does_not_follow_replaced_x_directory() {
        let temp = TempDir::named("x-remove-fd");
        let base = &temp.0;
        let x_dir = base.join("home/.tog/x");
        let root = x_dir.join("py-victim-test");
        let victim = base.join("victim");
        fs::create_dir_all(root.join(".tog/nested")).unwrap();
        fs::write(root.join(".tog/nested/old"), b"old").unwrap();
        fs::create_dir_all(&victim).unwrap();
        fs::write(victim.join("keep"), b"keep").unwrap();
        std::os::unix::fs::symlink(&victim, root.join("victim-link")).unwrap();

        let validated = validated_x_dir(&x_dir).unwrap().expect("x directory");
        let root_fd =
            store::open_directory_at(validated.directory.as_raw_fd(), b"py-victim-test").unwrap();
        fs::rename(&x_dir, x_dir.with_extension("old")).unwrap();
        std::os::unix::fs::symlink(&victim, &x_dir).unwrap();

        store::remove_tree_at(root_fd.as_raw_fd()).unwrap();

        assert!(victim.join("keep").is_file());
        assert!(!root.join(".tog/nested/old").exists());
        drop(root_fd);
        drop(validated);
    }

    #[test]
    fn dot_prefixed_entries_are_not_x_candidates() {
        let temp = TempDir::named("x-lock-entry");
        let base = &temp.0;
        let x_dir = base.join("home/.tog/x");
        let root = x_dir.join("py-active");
        fs::create_dir_all(root.join(".tog/closures")).unwrap();
        let shared = lock_x_root(&root, false, false)
            .unwrap()
            .expect("active root shared lock");
        let lock_path = x_dir.join(".locks/py-active.lock");
        assert!(lock_path.is_file());
        fs::create_dir_all(x_dir.join(".locks/.tog")).unwrap();
        fs::write(x_dir.join(".locks/.tog/x.json"), "{}").unwrap();

        let candidates = x_candidates(&x_dir).unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].path, root.canonicalize().unwrap());
        assert!(
            candidates
                .iter()
                .all(|candidate| candidate.path != x_dir.join(".locks")),
            "the permanent lock directory was enumerated as an environment"
        );
        drop(shared);
    }

    #[test]
    fn clean_records_package_identity_not_executable_name() {
        let temp = TempDir::named("x-record");
        let base = &temp.0;
        let root = base.join("npm-scope-foo");
        fs::create_dir_all(root.join(".tog")).unwrap();
        write_x_request(&root, "node", "@scope/foo", None, "realizing").unwrap();
        let request = serde_json::from_reader::<_, serde_json::Value>(
            fs::File::open(root.join(X_REQUEST_FILE)).unwrap(),
        )
        .unwrap();
        assert_eq!(request["state"], "realizing");
        assert!(request.get("tool").is_none());

        let scoped = clean_filter(CleanRequest {
            ecosystem: Some("node".into()),
            from: None,
            tool: Some("@scope/foo".into()),
        })
        .unwrap();
        assert!(record_matches(&read_x_request(&root).unwrap(), &scoped));

        let from = clean_filter(CleanRequest {
            ecosystem: Some("python".into()),
            from: Some("httpie".into()),
            tool: Some("http".into()),
        })
        .unwrap();
        assert!(record_matches(
            &XRecord {
                ecosystem: "python".into(),
                package: "httpie".into(),
                version: None,
                state: Some("ready".into()),
                store_root: None,
            },
            &from
        ));
    }

    /// The request record names the originating store, and its registry
    /// entry is found there, not in the configured store.
    #[test]
    fn cleanup_finds_the_registration_in_the_recorded_store() {
        let temp = TempDir::named("x-registry");
        let base = &temp.0;
        let x_dir = base.join("x");
        let root = x_dir.join("py-ruff-registry");
        fs::create_dir_all(base.join("other-store/objects")).unwrap();
        fs::create_dir_all(base.join("other-store/meta")).unwrap();
        fs::create_dir_all(base.join("other-store/tmp")).unwrap();
        let store = Store::for_test(base.join("other-store").canonicalize().unwrap());
        let object = store.root.join("objects").join("a".repeat(40) + "-env");
        fs::create_dir_all(&object).unwrap();
        fs::create_dir_all(root.join(".tog/closures")).unwrap();
        fs::write(
            root.join(".tog/closures/python.json"),
            serde_json::json!({
                "schema": "closure/1",
                "ecosystem": "python",
                "body": {"env_object": object.display().to_string()}
            })
            .to_string(),
        )
        .unwrap();
        write_x_request_for_store(&root, &store, "python", "ruff", None, "ready", None).unwrap();
        crate::kernel::store::register_empty_root_for_test(&store, &root).unwrap();

        match registration_for(&root).unwrap() {
            Registration::Found {
                store: originating,
                entry,
            } => {
                assert_eq!(originating.root, store.root);
                assert_eq!(
                    entry.path.canonicalize().unwrap(),
                    root.canonicalize().unwrap()
                );
                originating.remove_root_entry(&entry).unwrap();
            }
            Registration::NotFound | Registration::Unknown | Registration::Unusable { .. } => {
                panic!("originating store registration was not found")
            }
        }
        assert!(store.roots().unwrap().is_empty());
    }

    #[test]
    fn realizing_marker_makes_partial_root_a_cleanup_candidate() {
        let temp = TempDir::named("x-partial");
        let base = &temp.0;
        let root = base.join("home/.tog/x/py-partial");
        ensure_x_metadata_dir(&root).unwrap();
        write_x_request(&root, "python", "ruff", None, "realizing").unwrap();
        let candidates = x_candidates(&base.join("home/.tog/x")).unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].path, root.canonicalize().unwrap());
    }

    /// Prepare an environment root the way the runner does, so cleanup will
    /// enumerate it: metadata directory plus a lifecycle marker.
    fn seed_root(root: &Path) {
        ensure_x_metadata_dir(root).unwrap();
        write_x_request(root, "python", "ruff", None, "realizing").unwrap();
    }

    /// `$HOME` on another volume is a routine setup, and `tog x` follows
    /// the symlink when it creates and registers a root. Cleanup has to reach
    /// exactly the same environment or it could never remove what the runner
    /// just made.
    #[test]
    fn runner_and_cleanup_agree_about_a_symlinked_home() {
        let temp = TempDir::named("x-symlinked-home");
        let base = &temp.0;
        let real_home = base.join("volume/home");
        fs::create_dir_all(&real_home).unwrap();
        let home = base.join("home");
        std::os::unix::fs::symlink(&real_home, &home).unwrap();

        let x_dir = home.join(".tog/x");
        let root = x_dir.join("py-linked-home");
        // Runner path: creates .tog/x, .locks and the root itself.
        let shared = acquire_x_root(&root).unwrap();
        seed_root(&root);
        assert!(real_home
            .join(".tog/x/.locks/py-linked-home.lock")
            .is_file());
        drop(shared);

        // Cleanup path: the same environment, named by its real location.
        let validated = validated_x_dir(&x_dir).unwrap().expect("x directory");
        assert_eq!(
            validated.path,
            real_home.canonicalize().unwrap().join(".tog/x")
        );
        let candidates = x_candidates(&x_dir).unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].path, root.canonicalize().unwrap());
        drop(validated);
    }

    /// The same contract for a symlinked `~/.tog` — "move the cache off
    /// the root disk".
    #[test]
    fn runner_and_cleanup_agree_about_a_symlinked_tog_directory() {
        let temp = TempDir::named("x-symlinked-tog");
        let base = &temp.0;
        let real_tog = base.join("volume/tog");
        fs::create_dir_all(&real_tog).unwrap();
        let home = base.join("home");
        fs::create_dir_all(&home).unwrap();
        std::os::unix::fs::symlink(&real_tog, home.join(".tog")).unwrap();

        let x_dir = home.join(".tog/x");
        let root = x_dir.join("py-linked-tog");
        let shared = acquire_x_root(&root).unwrap();
        seed_root(&root);
        assert!(real_tog.join("x/.locks/py-linked-tog.lock").is_file());
        drop(shared);

        let validated = validated_x_dir(&x_dir).unwrap().expect("x directory");
        assert_eq!(validated.path, real_tog.canonicalize().unwrap().join("x"));
        let candidates = x_candidates(&x_dir).unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].path, root.canonicalize().unwrap());
        drop(validated);
    }

    /// The final `x` component is where both commands stop following: the
    /// runner refuses it as a private directory and cleanup refuses to clean
    /// it, so neither can be pointed at a directory outside the home chain.
    #[test]
    fn runner_and_cleanup_both_refuse_a_symlinked_x_directory() {
        let temp = TempDir::named("x-symlinked-x");
        let base = &temp.0;
        let home = base.join("home");
        fs::create_dir_all(home.join(".tog")).unwrap();
        let elsewhere = base.join("elsewhere");
        fs::create_dir_all(&elsewhere).unwrap();
        let x_dir = home.join(".tog/x");
        std::os::unix::fs::symlink(&elsewhere, &x_dir).unwrap();

        let runner = open_x_dir(&x_dir).unwrap_err();
        assert!(
            runner.to_string().contains("is not a private directory"),
            "{runner}"
        );
        let cleanup = validated_x_dir(&x_dir).unwrap_err();
        assert!(
            cleanup
                .to_string()
                .contains("is a symlink; refusing to clean"),
            "{cleanup}"
        );
        assert!(elsewhere.is_dir(), "the symlink target was touched");
    }

    /// A relative `HOME` is still refused, by both commands, before anything
    /// is opened.
    #[test]
    fn cleanup_refuses_a_relative_home() {
        let error = validated_x_dir(Path::new("relative-home/.tog/x")).unwrap_err();
        assert!(error.to_string().contains("is not absolute"), "{error}");
    }

    /// A successful cleanup unlinks the lock file it holds so `.locks` cannot
    /// grow one stale file per environment ever created. A runner that was
    /// already waiting on that inode must not be handed a lock that protects
    /// nothing: it revalidates and locks the file the pathname names now.
    #[test]
    fn cleanup_unlinks_the_root_lock_and_a_waiter_relocks_the_new_file() {
        let temp = TempDir::named("x-lock-unlink");
        let base = &temp.0;
        let x_dir = base.join("home/.tog/x");
        let root = x_dir.join("py-unlink");
        fs::create_dir_all(&root).unwrap();
        let x_fd = open_directory_path(&x_dir.canonicalize().unwrap()).unwrap();
        let name = OsString::from("py-unlink");
        let cleanup = lock_x_root_at(x_fd.as_raw_fd(), &name, true, true)
            .unwrap()
            .expect("cleanup lock");
        let lock_path = x_dir.join(".locks/py-unlink.lock");
        assert!(lock_path.is_file());

        let (ready_tx, ready_rx) = mpsc::channel();
        let waiter_root = root.clone();
        let waiter = thread::spawn(move || {
            let lock = lock_x_root(&waiter_root, true, false)
                .unwrap()
                .expect("blocking lock");
            let identity = store::fd_identity(&lock).unwrap();
            ready_tx.send(identity).unwrap();
            lock
        });
        assert!(
            ready_rx
                .recv_timeout(std::time::Duration::from_millis(100))
                .is_err(),
            "the waiter took the lock while cleanup still held it"
        );

        remove_x_root_lock_at(x_fd.as_raw_fd(), &name).unwrap();
        assert!(
            !lock_path.exists(),
            "cleanup left its lock file behind: {}",
            lock_path.display()
        );
        drop(cleanup);

        let identity = ready_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("the waiter never acquired a lock after cleanup released it");
        let current = fs::symlink_metadata(&lock_path).expect("the waiter recreated the lock file");
        assert_eq!(
            identity,
            (current.dev(), current.ino()),
            "the waiter holds a lock on an inode the lock pathname no longer names"
        );
        drop(waiter.join().unwrap());
        // Unlinking twice is not an error: the file may already be gone.
        remove_x_root_lock_at(x_fd.as_raw_fd(), &name).unwrap();
        drop(x_fd);
    }

    /// The pending-exception queue is shared, so a test that asserts on its
    /// length starts from an empty queue under a lock of its own.
    fn exception_guard() -> std::sync::MutexGuard<'static, ()> {
        policy::exception_guard()
    }

    /// A published Python `x` root whose environment object carries
    /// `exceptions` in its metadata: (store, root, object).
    /// The cached projection's object, in the full object-id shape the
    /// cache check demands.
    const TEST_ENV: &str = "0123456789abcdef0123456789abcdef01234567-test-env";
    const TEST_NODE_ENV: &str = "0123456789abcdef0123456789abcdef01234567-test-node-env";

    fn ready_python_root(
        base: &Path,
        exceptions: &[serde_json::Value],
    ) -> (Store, PathBuf, PathBuf) {
        fs::create_dir_all(base.join("store/objects").join(TEST_ENV).join("bin")).unwrap();
        fs::create_dir_all(base.join("store/meta")).unwrap();
        // `Store::has_with_activity` takes the publish lock under `tmp/`.
        fs::create_dir_all(base.join("store/tmp")).unwrap();
        // Closures record the store's own canonical object path.
        let store = Store::for_test(base.join("store").canonicalize().unwrap());
        let object = store.object_path(TEST_ENV);
        let executable = object.join("bin/ruff");
        fs::write(&executable, "#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();
        // A complete object is a read-only directory with metadata.
        fs::set_permissions(&object, fs::Permissions::from_mode(0o555)).unwrap();
        fs::write(
            store.root.join(format!("meta/{TEST_ENV}.json")),
            serde_json::json!({"id": TEST_ENV, "exceptions": exceptions}).to_string(),
        )
        .unwrap();

        let root = base.join("home/.tog/x/py-ready");
        fs::create_dir_all(root.join(".tog/closures")).unwrap();
        std::os::unix::fs::symlink(&object, root.join(".venv")).unwrap();
        fs::write(
            root.join(".tog/closures/python.json"),
            serde_json::json!({
                "schema": "closure/1",
                "ecosystem": "python",
                "platform": Platform::host().unwrap().triple(),
                "body": {
                    "env_object": object.display().to_string(),
                    "exceptions": exceptions
                }
            })
            .to_string(),
        )
        .unwrap();
        write_x_request_for_store(&root, &store, "python", "ruff", None, "ready", None).unwrap();
        (store, root, object)
    }

    /// The cached environment id passes the same shape check the store
    /// applies: a name a plain character filter allows but no object can
    /// carry is refused before any store lookup.
    #[test]
    fn a_cached_environment_id_must_have_the_object_id_shape() {
        let _guard = exception_guard();
        let temp = TempDir::named("x-cached-id-shape");
        let (store, root, object) = ready_python_root(&temp.0, &[]);
        let activity = store
            .activity(crate::kernel::activity::ActivityMode::Shared)
            .unwrap();
        assert!(cached_projection(&store, &activity, &root, "python").is_ok());
        for id in ["test-env", "0123456789abcdef0123456789abcdef01234567-a..b"] {
            let closure = root.join(".tog/closures/python.json");
            let mut envelope: serde_json::Value =
                serde_json::from_str(&fs::read_to_string(&closure).unwrap()).unwrap();
            envelope["body"]["env_object"] = store.object_path(id).display().to_string().into();
            fs::write(&closure, envelope.to_string()).unwrap();
            let error = cached_projection(&store, &activity, &root, "python").unwrap_err();
            assert!(
                error.to_string().contains("malformed environment object"),
                "{id}: {error}"
            );
        }
        drop(activity);
        fs::set_permissions(&object, fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// A cache hit validates the projection exactly once. `x_request_is_ready`
    /// ends with `check_cached_projection`, so a caller that validated again
    /// would narrate and queue every persisted exception twice.
    #[test]
    fn ready_cache_hit_records_each_exception_once() {
        let _guard = exception_guard();
        let _attribution = policy::Attribution::open("python").unwrap();
        let temp = TempDir::named("x-ready-exceptions");
        let base = &temp.0;
        let exception = serde_json::json!({
            "kind": policy::FILE_COLLISION,
            "subject": "ruff",
            "detail": "cached test exception"
        });
        let (store, root, object) = ready_python_root(base, &[exception]);
        let activity = store
            .activity(crate::kernel::activity::ActivityMode::Shared)
            .unwrap();

        assert!(policy::pending().is_empty());
        assert!(x_request_is_ready(
            &store,
            &activity,
            &root,
            "python",
            &root.join(".venv/bin/ruff")
        )
        .unwrap());
        assert_eq!(
            policy::pending().len(),
            1,
            "a cache hit narrated the same exception more than once: {:?}",
            policy::pending()
        );
        let _ = policy::drain();
        drop(activity);
        // The object is published read-only; make it removable again.
        fs::set_permissions(&object, fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// The cache check runs under the x-root lock, and GC takes the activity
    /// lock before the x-root lock. So the check must borrow the lease the
    /// caller already holds, never take one underneath the x-root lock. The
    /// caller here holds the exclusive lease: minting any lease on this
    /// thread would be refused, so a ready answer proves none was taken.
    #[test]
    fn the_x_cache_check_takes_no_lease_under_the_x_root_lock() {
        let _guard = exception_guard();
        let _attribution = policy::Attribution::open("python").unwrap();
        let temp = TempDir::named("x-borrowed-lease");
        let base = &temp.0;
        let (store, root, object) = ready_python_root(base, &[]);
        let exclusive = store
            .activity(crate::kernel::activity::ActivityMode::Exclusive)
            .unwrap();
        let _x_lock = acquire_x_root(&root).unwrap();
        assert!(x_request_is_ready(
            &store,
            &exclusive,
            &root,
            "python",
            &root.join(".venv/bin/ruff")
        )
        .unwrap());
        // The minting form the borrowed one replaced cannot even be taken on
        // this thread now.
        assert!(store.has(TEST_ENV).is_err());
        drop(exclusive);
        let _ = policy::drain();
        fs::set_permissions(&object, fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// A root with no request record is never a cache hit, however
    /// complete its projection: the same root with a `ready` record is one,
    /// and so the run rebuilds a record-less root rather than reusing it.
    #[test]
    fn a_root_without_a_request_record_is_never_a_cache_hit() {
        let _guard = exception_guard();
        let _attribution = policy::Attribution::open("python").unwrap();
        let temp = TempDir::named("x-no-record");
        let base = &temp.0;
        let (store, root, object) = ready_python_root(base, &[]);
        let activity = store
            .activity(crate::kernel::activity::ActivityMode::Shared)
            .unwrap();
        let executable = root.join(".venv/bin/ruff");
        assert!(x_request_is_ready(&store, &activity, &root, "python", &executable).unwrap());
        fs::remove_file(root.join(X_REQUEST_FILE)).unwrap();
        assert!(!x_request_is_ready(&store, &activity, &root, "python", &executable).unwrap());
        // An unreadable record and a run still realizing are not hits either.
        fs::write(root.join(X_REQUEST_FILE), "{").unwrap();
        assert!(!x_request_is_ready(&store, &activity, &root, "python", &executable).unwrap());
        write_x_request_for_store(&root, &store, "python", "ruff", None, "realizing", None)
            .unwrap();
        assert!(!x_request_is_ready(&store, &activity, &root, "python", &executable).unwrap());
        let _ = policy::drain();
        drop(activity);
        fs::set_permissions(&object, fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// A root with no request record cannot say what it was made for, so
    /// only the unfiltered clean selects it, and no store owns it.
    #[test]
    fn a_root_without_a_request_record_matches_only_an_unfiltered_clean() {
        let temp = TempDir::named("x-unrecorded");
        let base = &temp.0;
        let root = base.join("home/.tog/x/py-ruff-0123456789abcdef");
        fs::create_dir_all(root.join(".tog/closures")).unwrap();
        // Its closure names an object in some store: that is no longer
        // read as a claim of ownership.
        fs::write(
            root.join(".tog/closures/python.json"),
            serde_json::json!({
                "schema": "closure/1",
                "ecosystem": "python",
                "body": {"env_object": "/elsewhere/store/objects/0000000000000000000000000000000000000000-env"}
            })
            .to_string(),
        )
        .unwrap();
        let candidates = x_candidates(&base.join("home/.tog/x")).unwrap();
        assert_eq!(candidates.len(), 1);
        let filter = |ecosystem: Option<&str>, tool: Option<&str>| {
            clean_filter(CleanRequest {
                ecosystem: ecosystem.map(str::to_string),
                from: None,
                tool: tool.map(str::to_string),
            })
            .unwrap()
        };
        assert_eq!(
            candidate_matches(&candidates[0], &filter(None, None)),
            CandidateMatch::Match
        );
        for (ecosystem, tool) in [
            (None, Some("ruff")),
            (Some("python"), None),
            (Some("python"), Some("ruff")),
        ] {
            assert_eq!(
                candidate_matches(&candidates[0], &filter(ecosystem, tool)),
                CandidateMatch::NoMatch,
                "{ecosystem:?} {tool:?}"
            );
        }
        // Its closure names an object in a store that is not there, so no
        // owner can be recovered and cleanup would skip it.
        assert!(matches!(
            originating_store(&root).unwrap(),
            Origin::Unknown(why) if why.contains("is unavailable")
        ));
        assert!(matches!(
            registration_for(&root).unwrap(),
            Registration::Unknown
        ));
    }

    /// A closure directory cleanup cannot read leaves the owner unknown, so
    /// that root is skipped instead of stopping the whole clean.
    #[test]
    fn an_unreadable_closure_directory_leaves_the_owner_unknown() {
        use std::os::unix::fs::PermissionsExt;
        let temp = TempDir::named("x-unreadable-owner");
        let root = temp.0.join("py-ruff-0123456789abcdef");
        let closures = root.join(".tog/closures");
        fs::create_dir_all(&closures).unwrap();
        fs::write(closures.join("python.json"), b"{}").unwrap();
        fs::set_permissions(&closures, fs::Permissions::from_mode(0o000)).unwrap();
        let readable = fs::read_dir(&closures).is_ok();
        let origin = originating_store(&root);
        fs::set_permissions(&closures, fs::Permissions::from_mode(0o755)).unwrap();
        if readable {
            // Running as root: permissions do not bind, nothing to prove.
            return;
        }
        assert!(matches!(
            origin.unwrap(),
            Origin::Unknown(why) if why.contains("could not be read")
        ));
    }

    /// `candidate_ecosystem` decides which environments the clean summary
    /// calls node, so pin the order it reads: the recorded request, then
    /// the generated name prefix.
    #[test]
    fn candidate_ecosystem_reads_record_then_name() {
        let temp = TempDir::named("x-ecosystem");
        let base = &temp.0;
        let recorded = base.join("py-recorded");
        ensure_x_metadata_dir(&recorded).unwrap();
        write_x_request(&recorded, "node", "prettier", None, "ready").unwrap();
        assert_eq!(
            candidate_ecosystem(
                &open_directory_path(&recorded).unwrap(),
                recorded.file_name().unwrap()
            ),
            Some("node")
        );

        let named = base.join("npm-named");
        fs::create_dir_all(named.join(".tog")).unwrap();
        assert_eq!(
            candidate_ecosystem(
                &open_directory_path(&named).unwrap(),
                named.file_name().unwrap()
            ),
            Some("node")
        );

        let unknown = base.join("mystery");
        fs::create_dir_all(unknown.join(".tog")).unwrap();
        assert_eq!(
            candidate_ecosystem(
                &open_directory_path(&unknown).unwrap(),
                unknown.file_name().unwrap()
            ),
            None
        );
    }

    /// A pnpm cache root as `realize_cached_tool` leaves it after a finished
    /// run, minus its request record: the store's environment object, the
    /// `node-forest/2` projection its `node_modules` links into, and the
    /// `pnpm` executable. Returns (store, root, executable, object).
    fn pnpm_cache_without_record(base: &Path) -> (Store, PathBuf, PathBuf, PathBuf) {
        fs::create_dir_all(base.join("store/objects").join(TEST_NODE_ENV)).unwrap();
        fs::create_dir_all(base.join("store/meta")).unwrap();
        fs::create_dir_all(base.join("store/tmp")).unwrap();
        let store = Store::for_test(base.join("store").canonicalize().unwrap());
        let object = store.object_path(TEST_NODE_ENV);
        fs::set_permissions(&object, fs::Permissions::from_mode(0o555)).unwrap();
        fs::write(
            store.root.join(format!("meta/{TEST_NODE_ENV}.json")),
            serde_json::json!({"id": TEST_NODE_ENV, "exceptions": []}).to_string(),
        )
        .unwrap();

        let root = base.join("home/.tog/x/npm-pnpm-0123456789abcdef");
        fs::create_dir_all(root.join(".tog/closures")).unwrap();
        let projection_id = "ab".repeat(16);
        let key = hex::encode(Sha256::digest(
            root.canonicalize().unwrap().as_os_str().as_bytes(),
        ));
        let forest = store
            .root
            .join("forests")
            .join(&key[..32])
            .join(&projection_id)
            .join("node_modules");
        fs::create_dir_all(forest.join(".bin")).unwrap();
        let executable = forest.join(".bin/pnpm");
        fs::write(&executable, "#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();
        std::os::unix::fs::symlink(&forest, root.join("node_modules")).unwrap();
        fs::write(
            root.join(".tog/closures/node.json"),
            serde_json::json!({
                "schema": "closure/1",
                "ecosystem": "node",
                "platform": Platform::host().unwrap().triple(),
                "body": {
                    "env_object": object.display().to_string(),
                    "projection_schema": "node-forest/2",
                    "projection_id": projection_id,
                }
            })
            .to_string(),
        )
        .unwrap();
        (
            store,
            root.clone(),
            root.join("node_modules/.bin/pnpm"),
            object,
        )
    }

    /// The pnpm cache `realize_cached_tool` uses is reused only when its
    /// request record says `ready`, as `tog x` decides. One a tog before
    /// this record left (no `x.json`) and one an interrupted run left
    /// `realizing` are both marked `realizing` and rebuilt, never reused,
    /// though each holds a working `pnpm`.
    #[test]
    fn a_pnpm_cache_without_a_ready_record_is_rebuilt_not_reused() {
        let _guard = exception_guard();
        let _attribution = policy::Attribution::open("node").unwrap();
        let temp = TempDir::named("x-pnpm-cache");
        let (store, root, executable, object) = pnpm_cache_without_record(&temp.0);
        assert!(executable.is_file());
        let activity = store
            .activity(crate::kernel::activity::ActivityMode::Shared)
            .unwrap();
        let hit = |store: &Store| {
            cached_tool_hit(
                store,
                &activity,
                &root,
                "node",
                "pnpm",
                "9.1.0",
                &executable,
                None,
            )
            .unwrap()
        };
        let state = || read_x_request(&root).and_then(|record| record.state);

        // The control: the same root with a `ready` record is reused.
        write_x_request_for_store(&root, &store, "node", "pnpm", Some("9.1.0"), "ready", None)
            .unwrap();
        assert!(hit(&store));
        assert_eq!(state().as_deref(), Some("ready"));

        // Record-less: rebuilt.
        fs::remove_file(root.join(X_REQUEST_FILE)).unwrap();
        assert!(!hit(&store));
        assert_eq!(state().as_deref(), Some("realizing"));

        // Left `realizing` by an interrupted run: rebuilt again.
        assert!(!hit(&store));
        assert_eq!(state().as_deref(), Some("realizing"));

        let _ = policy::drain();
        drop(activity);
        fs::set_permissions(&object, fs::Permissions::from_mode(0o755)).unwrap();
    }
}

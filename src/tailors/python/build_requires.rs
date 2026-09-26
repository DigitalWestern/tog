//! Static inspection and resolution of PEP 517 build requirements.
//!
//! Inspection reads only archive metadata and pyproject.toml. Source is
//! executed only later, by pip inside the existing build sandbox.

use crate::kernel::activity::StoreActivity;
use crate::kernel::platform::Platform;
use crate::kernel::store::Store;
use crate::kernel::types::Plan;
use crate::tailors::python::pyselect;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};
use zip::ZipArchive;

const DEFAULT_REQUIRES: &[&str] = &["setuptools>=40.8.0", "wheel"];
const DEFAULT_BACKEND: &str = "setuptools.build_meta:__legacy__";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ArchiveInfo {
    pub archive_root: String,
    pub build_requires: Vec<String>,
    pub build_backend: String,
    /// Path relative to the extracted source root.
    pub cargo_manifest: Option<PathBuf>,
    pub rust_build: bool,
    /// The archive contains a source form that commonly triggers a native
    /// compile. This is deliberately a cheap scan of entry names (a
    /// `binding.gyp`, or a C/C++/Cython source): the native library object is
    /// mounted only for these builds.
    pub native_build: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArchiveKind {
    TarGz,
    Zip,
}

#[derive(Debug, Clone)]
struct ArchiveEntry {
    /// The name as stored in the archive.  Archive readers need this exact
    /// spelling (notably tar members prefixed with `./`).
    original: String,
    /// The validated, normalized spelling used for root and member checks.
    normalized: String,
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn archive_kind(path: &Path) -> io::Result<ArchiveKind> {
    let name = path.to_string_lossy().to_ascii_lowercase();
    if name.ends_with(".tar.gz") || name.ends_with(".tgz") {
        Ok(ArchiveKind::TarGz)
    } else if name.ends_with(".zip") {
        Ok(ArchiveKind::Zip)
    } else {
        // Verified artifact-cache entries are intentionally addressed by a
        // bare sha256, so identify those by their archive signature.
        let mut magic = [0u8; 4];
        let mut file = File::open(path)?;
        file.read_exact(&mut magic)?;
        match magic {
            [0x1f, 0x8b, ..] => Ok(ArchiveKind::TarGz),
            [b'P', b'K', 0x03, 0x04] | [b'P', b'K', 0x05, 0x06] => Ok(ArchiveKind::Zip),
            _ => Err(invalid(format!(
                "unsupported sdist archive {}; expected .tar.gz, .tgz, or .zip",
                path.display()
            ))),
        }
    }
}

fn clean_entry(raw: &str) -> io::Result<Option<String>> {
    let raw = raw.trim().trim_start_matches("./").trim_end_matches('/');
    if raw.is_empty() {
        return Ok(None);
    }
    if raw.starts_with('-') {
        return Err(invalid(format!(
            "sdist archive contains an option-like path {raw:?}"
        )));
    }
    let mut parts = Vec::new();
    for component in Path::new(raw).components() {
        match component {
            Component::Normal(part) => {
                let part = part
                    .to_str()
                    .ok_or_else(|| invalid("sdist archive contains a non-UTF-8 path"))?;
                parts.push(part.to_string());
            }
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(invalid(format!(
                    "sdist archive contains unsafe path {raw:?}"
                )))
            }
        }
    }
    if parts.is_empty() {
        Ok(None)
    } else {
        Ok(Some(parts.join("/")))
    }
}

fn tar_entries(path: &Path, activity: Option<&StoreActivity>) -> io::Result<Vec<ArchiveEntry>> {
    use crate::kernel::archive::Compression;
    let listed = match activity {
        Some(activity) => {
            crate::kernel::archive::list_with_activity(activity, path, Compression::Gzip)
        }
        None => crate::kernel::archive::list(path, Compression::Gzip),
    }
    .map_err(|e| io::Error::new(e.kind(), format!("list {}: {e}", path.display())))?;
    listed
        .into_iter()
        .map(|entry| {
            Ok(clean_entry(&entry.name)?.map(|normalized| ArchiveEntry {
                original: entry.name,
                normalized,
            }))
        })
        .filter_map(|entry| entry.transpose())
        .collect()
}

fn zip_entries(path: &Path) -> io::Result<Vec<ArchiveEntry>> {
    let file = File::open(path)?;
    let mut archive = ZipArchive::new(file)
        .map_err(|e| invalid(format!("read {} as zip: {e}", path.display())))?;
    let mut entries = Vec::new();
    for index in 0..archive.len() {
        let entry = archive
            .by_index(index)
            .map_err(|e| invalid(format!("read zip entry {index}: {e}")))?;
        if let Some(normalized) = clean_entry(entry.name())? {
            entries.push(ArchiveEntry {
                original: entry.name().to_string(),
                normalized,
            });
        }
    }
    Ok(entries)
}

fn entries(
    path: &Path,
    kind: ArchiveKind,
    activity: Option<&StoreActivity>,
) -> io::Result<Vec<ArchiveEntry>> {
    match kind {
        ArchiveKind::TarGz => tar_entries(path, activity),
        ArchiveKind::Zip => zip_entries(path),
    }
}

fn archive_root(entries: &[ArchiveEntry], path: &Path) -> io::Result<String> {
    let root = entries
        .iter()
        .find_map(|entry| {
            entry
                .normalized
                .split('/')
                .next()
                .filter(|part| !part.is_empty())
        })
        .ok_or_else(|| invalid(format!("sdist archive {} is empty", path.display())))?;
    let root = root.to_string();
    if entries.iter().any(|entry| {
        entry
            .normalized
            .split('/')
            .next()
            .map(|part| part != root)
            .unwrap_or(false)
    }) {
        return Err(invalid(format!(
            "sdist archive {} has multiple top-level roots",
            path.display()
        )));
    }
    Ok(root)
}

fn root_relative(entry: &str, root: &str) -> Option<String> {
    entry
        .strip_prefix(root)
        .and_then(|rest| rest.strip_prefix('/'))
        .filter(|rest| !rest.is_empty())
        .map(str::to_string)
}

fn archive_file(
    path: &Path,
    kind: ArchiveKind,
    member: &str,
    activity: Option<&StoreActivity>,
) -> io::Result<Vec<u8>> {
    match kind {
        ArchiveKind::TarGz => {
            // One manifest read, not an extraction: the bytes come from the
            // validated in-process stream, never from a second tar child.
            // 16 MiB covers any real manifest; anything larger is refused
            // rather than buffered.
            const MEMBER_CAP: u64 = 16 << 20;
            let bytes = match activity {
                Some(activity) => crate::kernel::archive::read_member_with_activity(
                    activity,
                    path,
                    crate::kernel::archive::Compression::Gzip,
                    member,
                    MEMBER_CAP,
                ),
                None => crate::kernel::archive::read_member(
                    path,
                    crate::kernel::archive::Compression::Gzip,
                    member,
                    MEMBER_CAP,
                ),
            }
            .map_err(|e| invalid(format!("read {member} from {}: {e}", path.display())))?;
            Ok(bytes)
        }
        ArchiveKind::Zip => {
            let file = File::open(path)?;
            let mut archive = ZipArchive::new(file)
                .map_err(|e| invalid(format!("read {} as zip: {e}", path.display())))?;
            let mut entry = archive
                .by_name(member)
                .map_err(|e| invalid(format!("read {member} from zip: {e}")))?;
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes)?;
            Ok(bytes)
        }
    }
}

fn parse_pyproject(
    bytes: &[u8],
    source: &str,
) -> io::Result<(Vec<String>, String, Option<String>)> {
    let text = std::str::from_utf8(bytes)
        .map_err(|e| invalid(format!("{source}: pyproject.toml is not UTF-8: {e}")))?;
    let value: toml::Value = toml::from_str(text)
        .map_err(|e| invalid(format!("{source}: malformed pyproject.toml: {e}")))?;
    let Some(build_system) = value.get("build-system") else {
        return Ok((
            DEFAULT_REQUIRES.iter().map(|s| (*s).to_string()).collect(),
            DEFAULT_BACKEND.to_string(),
            maturin_manifest(&value, source)?,
        ));
    };
    let table = build_system
        .as_table()
        .ok_or_else(|| invalid(format!("{source}: build-system must be a table")))?;
    let requires = table
        .get("requires")
        .ok_or_else(|| invalid(format!("{source}: build-system.requires is missing")))?
        .as_array()
        .ok_or_else(|| invalid(format!("{source}: build-system.requires must be a list")))?
        .iter()
        .map(|value| {
            value.as_str().map(str::to_string).ok_or_else(|| {
                invalid(format!(
                    "{source}: every build-system.requires item must be a string"
                ))
            })
        })
        .collect::<io::Result<Vec<_>>>()?;
    let backend = table
        .get("build-backend")
        .map(|value| {
            value.as_str().map(str::to_string).ok_or_else(|| {
                invalid(format!(
                    "{source}: build-system.build-backend must be a string"
                ))
            })
        })
        .transpose()?
        .unwrap_or_else(|| DEFAULT_BACKEND.to_string());
    Ok((requires, backend, maturin_manifest(&value, source)?))
}

fn maturin_manifest(value: &toml::Value, source: &str) -> io::Result<Option<String>> {
    let Some(maturin) = value
        .get("tool")
        .and_then(toml::Value::as_table)
        .and_then(|tool| tool.get("maturin"))
    else {
        return Ok(None);
    };
    let Some(table) = maturin.as_table() else {
        return Err(invalid(format!("{source}: tool.maturin must be a table")));
    };
    let Some(value) = table.get("manifest-path") else {
        return Ok(None);
    };
    let path = value.as_str().ok_or_else(|| {
        invalid(format!(
            "{source}: tool.maturin.manifest-path must be a string"
        ))
    })?;
    let path = clean_entry(path)?.ok_or_else(|| invalid("empty maturin manifest-path"))?;
    Ok(Some(path))
}

fn is_rust_backend(backend: &str) -> bool {
    let backend = backend.to_ascii_lowercase();
    backend.contains("maturin")
        || backend.contains("setuptools_rust")
        || backend.contains("setuptools-rust")
}

fn requirement_name(requirement: &str) -> Option<(&str, &str, bool)> {
    let requirement = requirement.split(';').next()?.trim();
    let mut end = requirement.len();
    for (index, byte) in requirement.bytes().enumerate() {
        if matches!(byte, b'<' | b'>' | b'=' | b'!' | b'~' | b'[' | b' ' | b'\t') {
            end = index;
            break;
        }
    }
    let name = requirement[..end].trim();
    if name.is_empty() {
        return None;
    }
    let extras = requirement[end..].trim_start().starts_with('[');
    let spec = requirement[end..].trim();
    Some((name, spec, extras))
}

fn normalized_name(name: &str) -> String {
    name.to_ascii_lowercase().replace(['_', '.'], "-")
}

pub(crate) fn fast_path(requires: &[String]) -> bool {
    requires.iter().all(|requirement| {
        let Some((name, spec, extras)) = requirement_name(requirement) else {
            return false;
        };
        if extras {
            return false;
        }
        let pinned = match normalized_name(name).as_str() {
            "setuptools" => "84.0.0",
            "wheel" => "0.48.0",
            "pip" => "26.2.1",
            _ => return false,
        };
        pyselect::matches_specifier(spec, pinned).unwrap_or(false)
    })
}

pub(crate) fn numpy_constraint(runtime_plan: Option<&Plan>) -> Option<String> {
    runtime_plan
        .and_then(|plan| {
            plan.packages
                .iter()
                .find(|pkg| normalized_name(&pkg.name) == "numpy")
        })
        .map(|pkg| format!("numpy=={}", pkg.version))
}

pub(crate) fn lock_cache_key(
    platform: Platform,
    python_version: &str,
    requires: &[String],
    numpy: Option<&str>,
) -> String {
    use sha2::{Digest, Sha256};
    let mut sorted = requires.to_vec();
    sorted.sort();
    let input = format!(
        "build-resolve/2\0{}\0{}\0{}\0{}",
        platform.triple(),
        python_version,
        sorted.join("\n"),
        numpy.unwrap_or("")
    );
    hex::encode(Sha256::digest(input.as_bytes()))
}

pub(crate) fn resolve_build_plan(
    store: &Store,
    activity: &StoreActivity,
    platform: Platform,
    selected: &crate::kernel::toolchain::Selected,
    requires: &[String],
    runtime_plan: Option<&Plan>,
) -> io::Result<Plan> {
    let python_version = selected.version("cpython")?;
    let numpy = numpy_constraint(runtime_plan);
    let key = lock_cache_key(platform, python_version, requires, numpy.as_deref());
    let lock_path = store.cache_path("build-lock", &key);
    let plan_path = store.cache_path("build-plan", &key);
    fs::create_dir_all(lock_path.parent().expect("cache parent"))?;
    fs::create_dir_all(plan_path.parent().expect("cache parent"))?;
    let lock = match fs::read_to_string(&lock_path) {
        Ok(lock) => lock,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let text = requires_resolution_text(requires);
            let lock = crate::tailors::python::pypi::lock_requirement_text_with_uv(
                store,
                activity,
                platform,
                &text,
                selected,
                numpy.as_deref(),
            )?;
            fs::write(&lock_path, &lock)?;
            lock
        }
        Err(error) => return Err(error),
    };
    if let Ok(text) = fs::read_to_string(&plan_path) {
        if let Ok(plan) = serde_json::from_str(&text) {
            return Ok(plan);
        }
    }
    // Cache selected URLs too: a warm build needs neither uv nor PyPI JSON.
    let plan = crate::tailors::python::pypi::plan_python(platform, &lock, python_version)?;
    fs::write(&plan_path, serde_json::to_vec(&plan)?)?;
    Ok(plan)
}

fn requires_resolution_text(requires: &[String]) -> String {
    let mut requested = requires.to_vec();
    requested.push("pip==26.2.1".into());
    requested.join("\n") + "\n"
}

#[cfg(test)]
pub(crate) fn inspect_sdist(path: &Path) -> io::Result<ArchiveInfo> {
    inspect_sdist_inner(path, None)
}

pub(crate) fn inspect_sdist_for(activity: &StoreActivity, path: &Path) -> io::Result<ArchiveInfo> {
    inspect_sdist_inner(path, Some(activity))
}

fn inspect_sdist_inner(path: &Path, activity: Option<&StoreActivity>) -> io::Result<ArchiveInfo> {
    let kind = archive_kind(path)?;
    let entries = entries(path, kind, activity)?;
    let root = archive_root(&entries, path)?;
    let pyproject_member = format!("{root}/pyproject.toml");
    let pyproject_entry = entries
        .iter()
        .find(|entry| entry.normalized == pyproject_member);
    let (requires, backend, explicit_manifest) = if let Some(entry) = pyproject_entry {
        parse_pyproject(
            &archive_file(path, kind, &entry.original, activity)?,
            &pyproject_member,
        )?
    } else {
        (
            DEFAULT_REQUIRES.iter().map(|s| (*s).to_string()).collect(),
            DEFAULT_BACKEND.to_string(),
            None,
        )
    };
    let explicit_manifest = explicit_manifest
        .map(|manifest| {
            if !entries.iter().any(|entry| {
                root_relative(&entry.normalized, &root).as_deref() == Some(manifest.as_str())
            }) {
                return Err(invalid(format!(
                    "sdist build backend points to missing Cargo manifest {manifest}"
                )));
            }
            Ok(PathBuf::from(manifest))
        })
        .transpose()?;
    let cargo_manifest = explicit_manifest.or_else(|| {
        ["Cargo.toml", "bindings/python/Cargo.toml"]
            .iter()
            .find(|candidate| {
                entries.iter().any(|entry| {
                    root_relative(&entry.normalized, &root).as_deref() == Some(**candidate)
                })
            })
            .map(PathBuf::from)
    });
    let native_build = entries.iter().any(|entry| {
        let Some(relative) = root_relative(&entry.normalized, &root) else {
            return false;
        };
        let path = Path::new(&relative);
        path.file_name().and_then(|name| name.to_str()) == Some("binding.gyp")
            || matches!(
                path.extension().and_then(|extension| extension.to_str()),
                Some("c") | Some("cc") | Some("cpp") | Some("cxx") | Some("C") | Some("pyx")
            )
    });
    let rust_build = cargo_manifest.is_some()
        || is_rust_backend(&backend)
        || requires.iter().any(|requirement| {
            requirement_name(requirement)
                .map(|(name, _, _)| {
                    matches!(
                        normalized_name(name).as_str(),
                        "maturin" | "setuptools-rust"
                    )
                })
                .unwrap_or(false)
        });
    Ok(ArchiveInfo {
        archive_root: root,
        build_requires: requires,
        build_backend: backend,
        cargo_manifest,
        rust_build,
        native_build,
    })
}

#[cfg(test)]
pub(crate) fn extract_sdist(
    path: &Path,
    destination: &Path,
    info: &ArchiveInfo,
) -> io::Result<PathBuf> {
    extract_sdist_inner(path, destination, info, None)
}

pub(crate) fn extract_sdist_for(
    activity: &StoreActivity,
    path: &Path,
    destination: &Path,
    info: &ArchiveInfo,
) -> io::Result<PathBuf> {
    extract_sdist_inner(path, destination, info, Some(activity))
}

fn extract_sdist_inner(
    path: &Path,
    destination: &Path,
    info: &ArchiveInfo,
    activity: Option<&StoreActivity>,
) -> io::Result<PathBuf> {
    fs::create_dir_all(destination)?;
    match archive_kind(path)? {
        ArchiveKind::TarGz => {
            // The listing validates every member before the delegated tar
            // writes anything. The same check runs in inspect_sdist, but
            // extract_sdist is also used directly in the Rust planning path.
            use crate::kernel::archive::Compression;
            let listed = match activity {
                Some(activity) => {
                    crate::kernel::archive::list_with_activity(activity, path, Compression::Gzip)
                }
                None => crate::kernel::archive::list(path, Compression::Gzip),
            }
            .map_err(|e| io::Error::new(e.kind(), format!("extract {}: {e}", path.display())))?;
            // Keep the name-shape check the inspect path applies, so a
            // direct extract refuses exactly what inspection would refuse.
            for entry in &listed {
                clean_entry(&entry.name)?;
            }
            match activity {
                Some(activity) => crate::kernel::archive::extract_validated_with_activity(
                    activity,
                    path,
                    destination,
                    1,
                    Compression::Gzip,
                    &listed,
                ),
                None => crate::kernel::archive::extract_validated(
                    path,
                    destination,
                    1,
                    Compression::Gzip,
                    &listed,
                ),
            }
            .map_err(|e| io::Error::new(e.kind(), format!("extract {}: {e}", path.display())))?;
        }
        ArchiveKind::Zip => {
            let file = File::open(path)?;
            let mut archive = ZipArchive::new(file)
                .map_err(|e| invalid(format!("read {} as zip: {e}", path.display())))?;
            for index in 0..archive.len() {
                let mut entry = archive
                    .by_index(index)
                    .map_err(|e| invalid(format!("read zip entry {index}: {e}")))?;
                if entry.is_symlink() {
                    return Err(invalid(format!(
                        "sdist archive contains a symlink entry: {}",
                        entry.name()
                    )));
                }
                let Some(name) = clean_entry(entry.name())? else {
                    continue;
                };
                let Some(relative) = root_relative(&name, &info.archive_root) else {
                    continue;
                };
                let output = destination.join(&relative);
                if entry.is_dir() {
                    fs::create_dir_all(&output)?;
                    continue;
                }
                if let Some(parent) = output.parent() {
                    fs::create_dir_all(parent)?;
                }
                let mut bytes = Vec::new();
                entry.read_to_end(&mut bytes)?;
                fs::write(output, bytes)?;
            }
        }
    }
    let source = destination.canonicalize()?;
    validate_extracted_links(&source)?;
    if let Some(manifest) = &info.cargo_manifest {
        let path = source.join(manifest);
        if !path.starts_with(&source) || !path.is_file() {
            return Err(invalid(format!(
                "extracted Cargo manifest is missing: {}",
                path.display()
            )));
        }
    }
    Ok(source)
}

fn validate_extracted_links(root: &Path) -> io::Result<()> {
    fn walk(root: &Path, path: &Path) -> io::Result<()> {
        let metadata = fs::symlink_metadata(path)?;
        let file_type = metadata.file_type();
        if file_type.is_symlink() {
            let target = fs::read_link(path)?;
            if target.is_absolute() || !link_target_within(root, path, &target)? {
                return Err(invalid(format!(
                    "extracted sdist link escapes the source root: {} -> {}",
                    path.display(),
                    target.display()
                )));
            }
            return Ok(());
        }
        if file_type.is_dir() {
            for entry in fs::read_dir(path)? {
                walk(root, &entry?.path())?;
            }
            return Ok(());
        }
        if file_type.is_file() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if metadata.nlink() > 1 {
                    return Err(invalid(format!(
                        "extracted sdist contains a hard link: {}",
                        path.display()
                    )));
                }
            }
            return Ok(());
        }
        Err(invalid(format!(
            "extracted sdist contains a special file: {}",
            path.display()
        )))
    }

    walk(root, root)
}

/// Resolve a link lexically while following existing symlinks.  This also
/// catches a relative link whose apparent target is inside the tree but which
/// passes through another symlink to outside it.  Missing final targets are
/// allowed as long as their lexical path remains inside the root.
fn link_target_within(root: &Path, link: &Path, target: &Path) -> io::Result<bool> {
    use std::collections::VecDeque;
    use std::ffi::OsString;

    if target.is_absolute() {
        return Ok(false);
    }
    let candidate = link
        .parent()
        .ok_or_else(|| invalid("extracted sdist link has no parent"))?
        .join(target);
    let relative = candidate
        .strip_prefix(root)
        .map_err(|_| invalid("extracted sdist link is outside its source root"))?;
    let mut pending: VecDeque<OsString> = relative
        .components()
        .map(|component| component.as_os_str().to_os_string())
        .collect();
    let mut current = root.to_path_buf();
    let mut symlink_count = 0;
    while let Some(component) = pending.pop_front() {
        if component == "." {
            continue;
        }
        if component == ".." {
            if current == root || !current.pop() {
                return Ok(false);
            }
            continue;
        }
        let next = current.join(&component);
        match fs::symlink_metadata(&next) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                symlink_count += 1;
                if symlink_count > 40 {
                    return Err(invalid("extracted sdist contains a symlink loop"));
                }
                let nested = fs::read_link(&next)?;
                if nested.is_absolute() {
                    return Ok(false);
                }
                let mut replacement: VecDeque<OsString> = nested
                    .components()
                    .map(|component| component.as_os_str().to_os_string())
                    .collect();
                replacement.append(&mut pending);
                pending = replacement;
            }
            Ok(_) => current = next,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                // There cannot be a symlink below a missing component.  Keep
                // processing the remaining components so `..` still cannot
                // cross the root boundary.
                current = next;
            }
            Err(error) if error.kind() == io::ErrorKind::NotADirectory => {
                return Ok(true);
            }
            Err(error) => return Err(error),
        }
    }
    Ok(current.starts_with(root))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::testutil::TempDir;
    use std::io::Write;
    use std::process::Command;

    fn temp_dir(label: &str) -> TempDir {
        TempDir::named(&format!("build-requires-{label}"))
    }

    fn archive(path: &Path, format: ArchiveKind, pyproject: Option<&[u8]>) {
        let root = path.parent().unwrap().join("example-1.0");
        fs::create_dir_all(&root).unwrap();
        if let Some(bytes) = pyproject {
            fs::write(root.join("pyproject.toml"), bytes).unwrap();
        }
        match format {
            ArchiveKind::TarGz => {
                let status = Command::new("/usr/bin/tar")
                    .args(["-czf"])
                    .arg(path)
                    .args(["-C"])
                    .arg(path.parent().unwrap())
                    .arg("example-1.0")
                    .status()
                    .unwrap();
                assert!(status.success());
            }
            ArchiveKind::Zip => {
                let file = File::create(path).unwrap();
                let mut zip = zip::ZipWriter::new(file);
                if let Some(bytes) = pyproject {
                    zip.start_file(
                        "example-1.0/pyproject.toml",
                        zip::write::SimpleFileOptions::default(),
                    )
                    .unwrap();
                    zip.write_all(bytes).unwrap();
                } else {
                    zip.add_directory("example-1.0/", zip::write::SimpleFileOptions::default())
                        .unwrap();
                }
                zip.finish().unwrap();
            }
        }
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn extracts_present_build_system_from_tar_and_zip() {
        let text = br#"[build-system]
requires = ["hatchling>=1"]
build-backend = "hatchling.build"
"#;
        for (name, format) in [
            ("present.tar.gz", ArchiveKind::TarGz),
            ("present.zip", ArchiveKind::Zip),
        ] {
            let dir = temp_dir("present");
            let path = dir.0.join(name);
            archive(&path, format, Some(text));
            let info = inspect_sdist(&path).unwrap();
            assert_eq!(info.build_requires, vec!["hatchling>=1"]);
            assert_eq!(info.build_backend, "hatchling.build");
        }
    }

    #[test]
    fn absent_build_system_uses_pep517_legacy_default() {
        for (name, format) in [
            ("absent.tar.gz", ArchiveKind::TarGz),
            ("absent.zip", ArchiveKind::Zip),
        ] {
            let dir = temp_dir("absent");
            let path = dir.0.join(name);
            archive(&path, format, None);
            let info = inspect_sdist(&path).unwrap();
            assert_eq!(
                info.build_requires,
                vec!["setuptools>=40.8.0".to_string(), "wheel".to_string()]
            );
            assert_eq!(info.build_backend, DEFAULT_BACKEND);
        }
    }

    #[test]
    fn malformed_build_system_is_invalid_data_for_tar_and_zip() {
        let text = b"[build-system]\nrequires = \"not-a-list\"\n";
        for (name, format) in [
            ("malformed.tar.gz", ArchiveKind::TarGz),
            ("malformed.zip", ArchiveKind::Zip),
        ] {
            let dir = temp_dir("malformed");
            let path = dir.0.join(name);
            archive(&path, format, Some(text));
            let error = inspect_sdist(&path).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        }
    }

    #[test]
    fn rejects_option_like_tar_root_without_executing_it() {
        let dir = temp_dir("tar-injection");
        let root_name = "--checkpoint-action=exec=touch marker;#";
        let root = dir.0.join(root_name);
        fs::create_dir_all(&root).unwrap();
        fs::write(
            root.join("pyproject.toml"),
            b"[build-system]\nrequires = []\n",
        )
        .unwrap();
        let archive = dir.0.join("malicious.tar.gz");
        let status = Command::new("/usr/bin/tar")
            .args(["-czf"])
            .arg(&archive)
            .args(["-C"])
            .arg(&dir.0)
            .arg("--")
            .arg(root_name)
            .status()
            .unwrap();
        assert!(status.success());
        fs::remove_dir_all(&root).unwrap();

        let marker = std::env::current_dir().unwrap().join("marker");
        let _ = fs::remove_file(&marker);
        let error = inspect_sdist(&archive).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(!marker.exists(), "tar option-like member was executed");
    }

    #[test]
    fn tar_member_with_dot_prefix_is_inspected() {
        let dir = temp_dir("dot-prefix");
        let root = dir.0.join("example-1.0");
        fs::create_dir_all(&root).unwrap();
        fs::write(
            root.join("pyproject.toml"),
            b"[build-system]\nrequires = [\"hatchling>=1\"]\nbuild-backend = \"hatchling.build\"\n",
        )
        .unwrap();
        let path = dir.0.join("dot-prefix.tar.gz");
        let status = Command::new("/usr/bin/tar")
            .args(["-czf"])
            .arg(&path)
            .args(["-C"])
            .arg(&dir.0)
            .arg("./example-1.0")
            .status()
            .unwrap();
        assert!(status.success());
        fs::remove_dir_all(&root).unwrap();

        let info = inspect_sdist(&path).unwrap();
        assert_eq!(info.build_requires, vec!["hatchling>=1"]);
        assert_eq!(info.build_backend, "hatchling.build");
    }

    #[cfg(unix)]
    #[test]
    fn rejects_archive_symlink_escape_before_cargo_work() {
        use std::os::unix::fs::symlink;

        let dir = temp_dir("symlink-escape");
        let root = dir.0.join("example-1.0");
        fs::create_dir_all(&root).unwrap();
        fs::write(
            root.join("Cargo.toml"),
            b"[package]\nname = \"example\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .unwrap();
        let outside = std::env::temp_dir().join(format!("tog-escape-{}", std::process::id()));
        let _ = fs::remove_file(&outside);
        symlink(&outside, root.join("Cargo.lock")).unwrap();
        let path = dir.0.join("symlink-escape.tar.gz");
        let status = Command::new("/usr/bin/tar")
            .args(["-czf"])
            .arg(&path)
            .args(["-C"])
            .arg(&dir.0)
            .arg("example-1.0")
            .status()
            .unwrap();
        assert!(status.success());
        fs::remove_dir_all(&root).unwrap();

        let info = inspect_sdist(&path).unwrap();
        let error = extract_sdist(&path, &dir.0.join("source"), &info).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(
            !outside.exists(),
            "extraction created a file outside scratch"
        );
    }

    #[test]
    fn fast_path_predicate_covers_build_requirement_table() {
        let cases = [
            ("setuptools~=83.1", false),
            ("setuptools>=40.8", true),
            ("setuptools==84.0.0", true),
            ("setuptools==84.0.0rc1", false),
            ("setuptools<70", false),
            ("Cython", false),
            ("maturin>=1,<2", false),
            ("pip==26.2.1", true),
            ("wheel~=0.48", true),
            ("wheel!=0.48.0", false),
        ];
        for (requirement, expected) in cases {
            assert_eq!(fast_path(&[requirement.into()]), expected, "{requirement}");
        }
        assert!(is_rust_backend("maturin"));
        assert!(is_rust_backend("setuptools_rust.build"));
    }

    #[test]
    fn numpy_constraint_is_exact_runtime_version_only() {
        let plan = Plan {
            ecosystem: "python".into(),
            python_version: "3.12.14".into(),
            packages: vec![crate::kernel::types::LockedPackage {
                name: "NumPy".into(),
                version: "1.26.4".into(),
                filename: "numpy.whl".into(),
                url: String::new(),
                sha256: "a".repeat(64),
                kind: crate::kernel::types::ArtifactKind::Wheel,
                git: None,
            }],
        };
        assert_eq!(
            numpy_constraint(Some(&plan)).as_deref(),
            Some("numpy==1.26.4")
        );
        let without_numpy = Plan {
            ecosystem: "python".into(),
            python_version: "3.12.14".into(),
            packages: Vec::new(),
        };
        assert_eq!(numpy_constraint(Some(&without_numpy)), None);
        assert_eq!(numpy_constraint(None), None);
    }

    #[test]
    fn runtime_numpy_is_a_constraint_not_a_build_requirement() {
        let requirements = requires_resolution_text(&["setuptools>=40.8".into()]);
        assert!(requirements.lines().any(|line| line == "setuptools>=40.8"));
        assert!(requirements.lines().any(|line| line == "pip==26.2.1"));
        assert!(!requirements
            .lines()
            .any(|line| line.to_ascii_lowercase().starts_with("numpy")));
    }
}

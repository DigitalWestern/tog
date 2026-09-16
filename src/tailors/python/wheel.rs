//! Wheel installer: unpack a .whl into a target environment, PEP 427 style.
//!
//! IMPLEMENTATION CONTRACT (see install_wheel below) — being implemented.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::io::Read;
use std::path::{Path, PathBuf};

use zip::ZipArchive;

/// Install one wheel into an environment being assembled (PEP 427,
/// pragmatic subset). Routes `{name}.data/{purelib,platlib,headers,scripts,data}`,
/// rewrites `#!python` shebangs, generates console/gui-script launchers,
/// guards against zip-slip/symlinks, and lets a later wheel win collisions.
/// Known v0 gap: RECORD is left as shipped (not verified or rewritten).
pub fn install_wheel(
    wheel_path: &Path,
    site_packages: &Path,
    bin_dir: &Path,
    python_minor: &str,
    python_exe: &Path,
    installed: &mut BTreeMap<std::path::PathBuf, String>,
) -> io::Result<()> {
    let file = fs::File::open(wheel_path)?;
    let mut archive = ZipArchive::new(file).map_err(zip_error)?;

    let distribution_id = scan_dist_info(&mut archive, wheel_path)?;
    let data_prefix = format!(
        "{}.data/",
        distribution_id
            .strip_suffix(".dist-info")
            .unwrap_or(&distribution_id)
    );
    let distribution_dir = distribution_id
        .strip_suffix(".dist-info")
        .and_then(|name| name.rsplit_once('-').map(|(name, _)| name))
        .unwrap_or(&distribution_id)
        .to_string();
    let distribution_name = distribution_dir.replace('_', "-");
    let entry_points = read_entry_points(&mut archive, &distribution_id)?;

    let env_root = bin_dir.parent().ok_or_else(|| {
        invalid_data(format!(
            "bin directory has no environment root: {}",
            bin_dir.display()
        ))
    })?;
    validate_python_minor(python_minor)?;
    let headers_dir = env_root
        .join("include/site")
        .join(format!("python{python_minor}"))
        .join(&distribution_dir);
    let mut directory_modes = Vec::new();

    const MAX_UNPACKED_BYTES: u64 = 4 * 1024 * 1024 * 1024; // 4 GiB aggregate
    let mut total_written: u64 = 0;

    for index in 0..archive.len() {
        let mut entry = archive.by_index(index).map_err(zip_error)?;
        let name = entry.name().to_string();
        let Some((base, relative, executable)) = route_entry(
            &name,
            &data_prefix,
            site_packages,
            &headers_dir,
            bin_dir,
            env_root,
        )?
        else {
            continue;
        };

        let destination = safe_destination(base, relative, env_root, &name)?;
        if entry.is_dir() {
            fs::create_dir_all(&destination)?;
            if let Some(mode) = entry.unix_mode() {
                directory_modes.push((destination, mode & 0o777));
            }
            continue;
        }

        if destination.symlink_metadata().is_ok() {
            resolve_file_collision(
                &destination,
                env_root,
                installed,
                &distribution_id,
                &distribution_name,
            )?;
        }
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)?;
        }
        total_written += entry.size();
        if total_written > MAX_UNPACKED_BYTES {
            return Err(invalid_data(format!(
                "wheel expands past {MAX_UNPACKED_BYTES} bytes; refusing (zip bomb guard)"
            )));
        }
        write_wheel_entry(&mut entry, &destination, executable, python_exe)?;
        installed.insert(destination, distribution_id.clone());
    }

    for (directory, mode) in directory_modes {
        set_mode(&directory, mode)?;
    }

    if let Some(entry_points) = entry_points {
        install_launchers(
            &entry_points,
            bin_dir,
            env_root,
            python_exe,
            &distribution_id,
            &distribution_name,
            installed,
        )?;
    }

    Ok(())
}

/// First pass over the archive: reject unsafe or symlink entries and return
/// the single `.dist-info` directory name the wheel declares.
fn scan_dist_info(archive: &mut ZipArchive<fs::File>, wheel_path: &Path) -> io::Result<String> {
    let mut dist_info: Option<String> = None;
    for index in 0..archive.len() {
        let entry = archive.by_index(index).map_err(zip_error)?;
        let name = entry.name();
        validate_entry_name(name)?;
        if entry.is_symlink() {
            return Err(invalid_data(format!(
                "symlink entry is not allowed: {name}"
            )));
        }
        let top_level = name.split('/').next().unwrap_or_default();
        if top_level.ends_with(".dist-info") {
            match &dist_info {
                None => dist_info = Some(top_level.to_string()),
                Some(existing) if existing == top_level => {}
                Some(existing) => {
                    return Err(invalid_data(format!(
                        "wheel has multiple .dist-info dirs: {existing}, {top_level}"
                    )))
                }
            }
        }
    }
    dist_info.ok_or_else(|| {
        invalid_data(format!(
            "{} contains no .dist-info directory; not a wheel",
            wheel_path.display()
        ))
    })
}

/// Read `{dist_info}/entry_points.txt`, if the wheel ships one.
fn read_entry_points(
    archive: &mut ZipArchive<fs::File>,
    dist_info: &str,
) -> io::Result<Option<String>> {
    let Ok(mut entry) = archive.by_name(&format!("{dist_info}/entry_points.txt")) else {
        return Ok(None);
    };
    let mut contents = String::new();
    entry.read_to_string(&mut contents)?;
    Ok(Some(contents))
}

/// Route one archive entry to its install base and relative path. Entries
/// under `{name}.data/` follow the sysconfig scheme they name; everything
/// else lands in site-packages. `Ok(None)` means "skip this entry" — a bare
/// `{name}.data/{scheme}` record with nothing after it.
fn route_entry<'a>(
    name: &'a str,
    data_prefix: &str,
    site_packages: &'a Path,
    headers_dir: &'a Path,
    bin_dir: &'a Path,
    env_root: &'a Path,
) -> io::Result<Option<(&'a Path, &'a str, bool)>> {
    let Some(rest) = name.strip_prefix(data_prefix) else {
        return Ok(Some((site_packages, name, false)));
    };
    let Some((kind, relative)) = rest.split_once('/') else {
        return Ok(None);
    };
    let routed = match kind {
        "purelib" | "platlib" => (site_packages, relative, false),
        "headers" => (headers_dir, relative, false),
        "scripts" => (bin_dir, relative, true),
        "data" => (env_root, relative, false),
        other => {
            return Err(invalid_data(format!(
                "unsupported wheel .data scheme '{other}' in {name}"
            )))
        }
    };
    Ok(Some(routed))
}

/// A later wheel may take over a path an earlier one installed; anything
/// else — the same wheel twice, or a file nobody claims — is an error.
fn resolve_file_collision(
    destination: &Path,
    env_root: &Path,
    installed: &BTreeMap<PathBuf, String>,
    distribution_id: &str,
    distribution_name: &str,
) -> io::Result<()> {
    match installed.get(destination) {
        Some(previous) if previous == distribution_id => Err(invalid_data(format!(
            "file collision: {} already exists in wheel {}",
            destination.display(),
            distribution_id
        ))),
        Some(previous) => supersede(destination, env_root, previous, distribution_name),
        None => Err(invalid_data(format!(
            "file collision: {} already exists (from an earlier wheel or entry)",
            destination.display()
        ))),
    }
}

/// The console-script flavour of [`resolve_file_collision`]; both failure
/// cases report the same message.
fn resolve_script_collision(
    destination: &Path,
    env_root: &Path,
    installed: &BTreeMap<PathBuf, String>,
    distribution_id: &str,
    distribution_name: &str,
) -> io::Result<()> {
    match installed.get(destination) {
        Some(previous) if previous != distribution_id => {
            supersede(destination, env_root, previous, distribution_name)
        }
        _ => Err(invalid_data(format!(
            "console-script collision: {}",
            destination.display()
        ))),
    }
}

/// Record the overwrite as a policy exception and drop the earlier file.
fn supersede(
    destination: &Path,
    env_root: &Path,
    previous: &str,
    distribution_name: &str,
) -> io::Result<()> {
    let subject = destination
        .strip_prefix(env_root)
        .unwrap_or(destination)
        .display()
        .to_string();
    crate::kernel::policy::record(
        crate::kernel::policy::FILE_COLLISION,
        &subject,
        &format!("{previous} and {distribution_name}"),
    )?;
    fs::remove_file(destination)
}

/// Unpack one file entry and set its mode. Scripts are buffered so a
/// `#!python` shebang can be pointed at the environment's interpreter.
fn write_wheel_entry(
    entry: &mut zip::read::ZipFile<'_>,
    destination: &Path,
    executable: bool,
    python_exe: &Path,
) -> io::Result<()> {
    if executable {
        // Scripts are small; buffer them for shebang rewriting.
        let mut contents = Vec::new();
        entry.read_to_end(&mut contents)?;
        if contents.starts_with(b"#!python") {
            contents = rewrite_shebang(&contents, python_exe);
        }
        fs::write(destination, contents)?;
    } else {
        let mut out = fs::File::create(destination)?;
        io::copy(entry, &mut out)?;
    }
    let mode = if executable {
        Some(0o755)
    } else {
        entry.unix_mode().map(|mode| (mode & 0o777).max(0o644))
    };
    if let Some(mode) = mode {
        set_mode(destination, mode)?;
    }
    Ok(())
}

/// Generate `console_scripts`/`gui_scripts` launchers into `bin_dir`.
fn install_launchers(
    entry_points: &str,
    bin_dir: &Path,
    env_root: &Path,
    python_exe: &Path,
    distribution_id: &str,
    distribution_name: &str,
    installed: &mut BTreeMap<PathBuf, String>,
) -> io::Result<()> {
    for (name, module, attr) in parse_entry_points(entry_points)? {
        let launcher = launcher_source(python_exe, &module, &attr);
        let destination = bin_dir.join(name);
        if destination.symlink_metadata().is_ok() {
            resolve_script_collision(
                &destination,
                env_root,
                installed,
                distribution_id,
                distribution_name,
            )?;
        }
        fs::create_dir_all(bin_dir)?;
        fs::write(&destination, launcher)?;
        set_mode(&destination, 0o755)?;
        installed.insert(destination, distribution_id.to_string());
    }
    Ok(())
}

/// The launcher script pip would have written for one entry point.
fn launcher_source(python_exe: &Path, module: &str, attr: &str) -> String {
    let attr0 = attr.split('.').next().unwrap();
    format!(
        concat!(
            "#!{}\n",
            "# -*- coding: utf-8 -*-\n",
            "import re, sys\n",
            "from {module} import {attr0}\n",
            "if __name__ == \"__main__\":\n",
            "    sys.argv[0] = re.sub(r\"(-script\\.pyw?|\\.exe)?$\", \"\", sys.argv[0])\n",
            "    sys.exit({attr}())\n",
        ),
        python_exe.display(),
        module = module,
        attr0 = attr0,
        attr = attr
    )
}

fn zip_error(error: zip::result::ZipError) -> io::Error {
    invalid_data(error.to_string())
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn validate_entry_name(name: &str) -> io::Result<()> {
    if name
        .as_bytes()
        .first()
        .is_some_and(|byte| *byte == b'/' || *byte == b'\\')
        || name.split(['/', '\\']).any(|component| component == "..")
    {
        return Err(invalid_data(format!("unsafe zip entry: {name}")));
    }
    let _ = normalized_relative_path(name)?;
    Ok(())
}

fn validate_python_minor(python_minor: &str) -> io::Result<()> {
    let mut components = python_minor.split('.');
    let valid = components
        .next()
        .is_some_and(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
        && components
            .next()
            .is_some_and(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
        && components.next().is_none();
    if !valid {
        return Err(invalid_data(format!(
            "invalid Python minor version for wheel headers: {python_minor}"
        )));
    }
    Ok(())
}

fn normalized_relative_path(name: &str) -> io::Result<PathBuf> {
    let bytes = name.as_bytes();
    let absolute = bytes
        .first()
        .is_some_and(|byte| *byte == b'/' || *byte == b'\\')
        || (bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':');
    if absolute {
        return Err(invalid_data(format!("unsafe zip entry: {name}")));
    }

    // Zip entry names are POSIX paths: only `/` separates components. A
    // literal backslash is an ordinary filename byte and must be preserved,
    // or a wheel that contains one would install differently than it did
    // before this normalization under the same env identity.
    let mut normalized = PathBuf::new();
    for component in name.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                if !normalized.pop() {
                    return Err(invalid_data(format!("unsafe zip entry: {name}")));
                }
            }
            component => normalized.push(component),
        }
    }
    Ok(normalized)
}

fn safe_destination(
    base: &Path,
    relative: &str,
    env_root: &Path,
    entry_name: &str,
) -> io::Result<PathBuf> {
    if !base.starts_with(env_root) {
        return Err(invalid_data(format!(
            "wheel destination escapes environment root: {entry_name}"
        )));
    }
    let relative = normalized_relative_path(relative)?;
    let destination = base.join(relative);
    if !destination.starts_with(env_root) {
        return Err(invalid_data(format!(
            "wheel destination escapes environment root: {entry_name}"
        )));
    }
    Ok(destination)
}

fn rewrite_shebang(contents: &[u8], python_exe: &Path) -> Vec<u8> {
    let newline = contents.iter().position(|byte| *byte == b'\n');
    let line_end = newline.map(|index| index + 1).unwrap_or(contents.len());
    let has_crlf = line_end > 1 && contents[line_end - 2] == b'\r';
    let mut rewritten = format!("#!{}", python_exe.display()).into_bytes();
    if newline.is_some() {
        if has_crlf {
            rewritten.extend_from_slice(b"\r\n");
        } else {
            rewritten.push(b'\n');
        }
    }
    rewritten.extend_from_slice(&contents[line_end..]);
    rewritten
}

fn parse_entry_points(text: &str) -> io::Result<Vec<(String, String, String)>> {
    let mut section = "";
    let mut entries = Vec::new();
    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            section = &line[1..line.len() - 1];
            continue;
        }
        if section != "console_scripts" && section != "gui_scripts" {
            continue;
        }
        let Some((name, value)) = line.split_once('=') else {
            continue;
        };
        let name = name.trim();
        if name.is_empty()
            || name == "."
            || name == ".."
            || name.contains('/')
            || name.contains('\\')
        {
            return Err(invalid_data(format!("invalid entry point name: {name}")));
        }
        let value = value.split('[').next().unwrap().trim();
        let Some((module, attr)) = value.split_once(':') else {
            return Err(invalid_data(format!("invalid entry point value: {value}")));
        };
        let module = module.trim();
        let attr = attr.trim();
        if module.is_empty() || attr.is_empty() || attr.split('.').any(|part| part.is_empty()) {
            return Err(invalid_data(format!("invalid entry point value: {value}")));
        }
        entries.push((name.to_string(), module.to_string(), attr.to_string()));
    }
    Ok(entries)
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::io::Write;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};
    use zip::write::SimpleFileOptions;
    use zip::ZipWriter;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let suffix = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path =
                env::temp_dir().join(format!("blanket-wheel-{}-{suffix}", std::process::id()));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn write_wheel(path: &Path, entries: &[(&str, &[u8])]) {
        let file = fs::File::create(path).unwrap();
        let mut writer = ZipWriter::new(file);
        for (name, contents) in entries {
            let options = SimpleFileOptions::default().unix_permissions(0o600);
            writer.start_file(*name, options).unwrap();
            writer.write_all(contents).unwrap();
        }
        writer.finish().unwrap();
    }

    #[test]
    fn installs_files_scripts_and_entry_points() {
        let temp = TempDir::new();
        let site = temp.path().join("lib/python3.12/site-packages");
        let bin = temp.path().join("bin");
        fs::create_dir_all(&site).unwrap();
        fs::create_dir_all(&bin).unwrap();
        let python = bin.join("python");
        let wheel = temp.path().join("demo.whl");
        let entry_points = b"# comment\n[console_scripts]\ntool = demo:main.sub [extra]\n[gui_scripts]\ngui = demo:gui\n";
        write_wheel(
            &wheel,
            &[
                ("demo/__init__.py", b"value = 1\n"),
                ("demo-1.0.dist-info/entry_points.txt", entry_points),
                ("demo-1.0.dist-info/RECORD", b""),
                ("demo-1.0.data/purelib/pure.py", b"pure = True\n"),
                (
                    "demo-1.0.data/scripts/demo-tool",
                    b"#!python\nprint('ok')\n",
                ),
                (
                    "demo-1.0.data/scripts/demo-window",
                    b"#!pythonw\nprint('window')\n",
                ),
                ("demo-1.0.data/scripts/no-shebang", b"print('plain')\n"),
                ("demo-1.0.data/scripts/raw.bin", &[0, 1, 255]),
                ("demo-1.0.data/data/share/demo.txt", b"shared\n"),
            ],
        );

        install_wheel(&wheel, &site, &bin, "3.12", &python, &mut BTreeMap::new()).unwrap();

        assert_eq!(
            fs::read(site.join("demo/__init__.py")).unwrap(),
            b"value = 1\n"
        );
        assert_eq!(fs::read(site.join("pure.py")).unwrap(), b"pure = True\n");
        assert_eq!(
            fs::read(temp.path().join("share/demo.txt")).unwrap(),
            b"shared\n"
        );
        assert_eq!(
            fs::read(bin.join("demo-tool")).unwrap(),
            format!("#!{}\nprint('ok')\n", python.display()).as_bytes()
        );
        assert_eq!(
            fs::read(bin.join("demo-window")).unwrap(),
            format!("#!{}\nprint('window')\n", python.display()).as_bytes()
        );
        assert_eq!(
            fs::read(bin.join("no-shebang")).unwrap(),
            b"print('plain')\n"
        );
        assert_eq!(fs::read(bin.join("raw.bin")).unwrap(), &[0, 1, 255]);
        assert_eq!(
            fs::read_to_string(bin.join("tool")).unwrap(),
            format!(
                "#!{}\n# -*- coding: utf-8 -*-\nimport re, sys\nfrom demo import main\nif __name__ == \"__main__\":\n    sys.argv[0] = re.sub(r\"(-script\\.pyw?|\\.exe)?$\", \"\", sys.argv[0])\n    sys.exit(main.sub())\n",
                python.display()
            )
        );
        assert_eq!(
            fs::read_to_string(bin.join("gui")).unwrap(),
            format!(
                "#!{}\n# -*- coding: utf-8 -*-\nimport re, sys\nfrom demo import gui\nif __name__ == \"__main__\":\n    sys.argv[0] = re.sub(r\"(-script\\.pyw?|\\.exe)?$\", \"\", sys.argv[0])\n    sys.exit(gui())\n",
                python.display()
            )
        );

        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(bin.join("demo-tool"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o755
        );
        for script in ["demo-window", "no-shebang"] {
            assert_eq!(
                fs::metadata(bin.join(script)).unwrap().permissions().mode() & 0o777,
                0o755
            );
        }
        assert_eq!(
            fs::metadata(bin.join("raw.bin"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o755
        );
        assert_eq!(
            fs::metadata(bin.join("tool")).unwrap().permissions().mode() & 0o777,
            0o755
        );
        assert_eq!(
            fs::metadata(site.join("demo/__init__.py"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o644
        );
    }

    #[test]
    fn rejects_zip_slip_entry() {
        let temp = TempDir::new();
        let site = temp.path().join("site");
        let bin = temp.path().join("bin");
        fs::create_dir_all(&site).unwrap();
        fs::create_dir_all(&bin).unwrap();
        let wheel = temp.path().join("bad.whl");
        write_wheel(&wheel, &[("../escaped.txt", b"nope")]);

        let error = install_wheel(
            &wheel,
            &site,
            &bin,
            "3.12",
            &bin.join("python"),
            &mut BTreeMap::new(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("../escaped.txt"));
        assert!(!temp.path().join("escaped.txt").exists());
    }

    #[test]
    fn later_wheel_in_sorted_order_wins_collision() {
        let _attribution_lock = crate::kernel::policy::exception_guard();
        let _attribution = crate::kernel::policy::Attribution::open("python").unwrap();
        let temp = TempDir::new();
        let site = temp.path().join("site");
        let bin = temp.path().join("bin");
        fs::create_dir_all(&site).unwrap();
        fs::create_dir_all(&bin).unwrap();
        let first = temp.path().join("a-1.0.whl");
        let second = temp.path().join("b-1.0.whl");
        write_wheel(
            &first,
            &[("shared.py", b"first\n"), ("a-1.0.dist-info/RECORD", b"")],
        );
        write_wheel(
            &second,
            &[("shared.py", b"second\n"), ("b-1.0.dist-info/RECORD", b"")],
        );
        let mut wheels = vec![second, first];
        wheels.sort();
        let _ = crate::kernel::policy::drain();
        let mut installed = BTreeMap::new();
        for wheel in wheels {
            install_wheel(
                &wheel,
                &site,
                &bin,
                "3.12",
                &bin.join("python"),
                &mut installed,
            )
            .unwrap();
        }
        assert_eq!(
            fs::read_to_string(site.join("shared.py")).unwrap(),
            "second\n"
        );
        assert_eq!(crate::kernel::policy::drain().len(), 1);
    }

    #[test]
    fn literal_backslash_in_entry_name_is_preserved() {
        assert_eq!(
            normalized_relative_path("demo/a\\b.txt").unwrap(),
            PathBuf::from("demo/a\\b.txt")
        );
        assert_eq!(
            normalized_relative_path("./demo//x.py").unwrap(),
            PathBuf::from("demo/x.py")
        );
        assert!(normalized_relative_path("/abs").is_err());
        assert!(normalized_relative_path("../up").is_err());
        assert!(normalized_relative_path("demo/../../up").is_err());
    }

    #[test]
    fn installs_headers_in_venv_include_site() {
        let temp = TempDir::new();
        let site = temp.path().join("lib/python3.12/site-packages");
        let bin = temp.path().join("bin");
        fs::create_dir_all(&site).unwrap();
        fs::create_dir_all(&bin).unwrap();
        let wheel = temp.path().join("demo-1.0.whl");
        write_wheel(
            &wheel,
            &[
                ("demo-1.0.dist-info/RECORD", b""),
                ("demo-1.0.data/headers/demo.h", b"#define DEMO 1\n"),
                ("demo-1.0.data/headers/sub/x.h", b"#define DEMO_X 1\n"),
            ],
        );

        install_wheel(
            &wheel,
            &site,
            &bin,
            "3.12",
            &bin.join("python"),
            &mut BTreeMap::new(),
        )
        .unwrap();

        let headers = temp.path().join("include/site/python3.12/demo");
        assert_eq!(
            fs::read(headers.join("demo.h")).unwrap(),
            b"#define DEMO 1\n"
        );
        assert_eq!(
            fs::read(headers.join("sub/x.h")).unwrap(),
            b"#define DEMO_X 1\n"
        );
    }

    #[test]
    fn headers_preserve_underscore_in_distribution_name() {
        let temp = TempDir::new();
        let site = temp.path().join("lib/python3.12/site-packages");
        let bin = temp.path().join("bin");
        fs::create_dir_all(&site).unwrap();
        fs::create_dir_all(&bin).unwrap();
        let wheel = temp.path().join("foo_bar-1.0.whl");
        write_wheel(
            &wheel,
            &[
                ("foo_bar-1.0.dist-info/RECORD", b""),
                ("foo_bar-1.0.data/headers/foo.h", b"/* foo_bar */\n"),
            ],
        );

        install_wheel(
            &wheel,
            &site,
            &bin,
            "3.12",
            &bin.join("python"),
            &mut BTreeMap::new(),
        )
        .unwrap();

        assert!(temp
            .path()
            .join("include/site/python3.12/foo_bar/foo.h")
            .is_file());
        assert!(!temp
            .path()
            .join("include/site/python3.12/foo-bar/foo.h")
            .exists());
    }

    #[test]
    fn rejects_absolute_and_escaping_data_destinations() {
        let temp = TempDir::new();
        let site = temp.path().join("lib/python3.12/site-packages");
        let bin = temp.path().join("bin");
        fs::create_dir_all(&site).unwrap();
        fs::create_dir_all(&bin).unwrap();

        for (index, data_entry) in [
            ("absolute", "demo-1.0.data/data//outside.txt"),
            ("escaping", "demo-1.0.data/data/sub/../../outside.txt"),
        ] {
            let wheel = temp.path().join(format!("bad-{index}.whl"));
            write_wheel(
                &wheel,
                &[(data_entry, b"nope"), ("demo-1.0.dist-info/RECORD", b"")],
            );

            let error = install_wheel(
                &wheel,
                &site,
                &bin,
                "3.12",
                &bin.join("python"),
                &mut BTreeMap::new(),
            )
            .unwrap_err();
            assert!(error.to_string().contains("unsafe zip entry"), "{error}");
            assert!(!temp.path().join("outside.txt").exists());
        }
    }

    #[test]
    fn rejects_wheels_without_exactly_one_dist_info() {
        let temp = TempDir::new();
        let site = temp.path().join("lib/python3.12/site-packages");
        let bin = temp.path().join("bin");
        fs::create_dir_all(&site).unwrap();
        fs::create_dir_all(&bin).unwrap();

        let missing = temp.path().join("missing.whl");
        write_wheel(&missing, &[("demo/__init__.py", b"value = 1\n")]);
        let error = install_wheel(
            &missing,
            &site,
            &bin,
            "3.12",
            &bin.join("python"),
            &mut BTreeMap::new(),
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(
            error
                .to_string()
                .contains("contains no .dist-info directory; not a wheel"),
            "{error}"
        );

        let doubled = temp.path().join("doubled.whl");
        write_wheel(
            &doubled,
            &[
                ("demo-1.0.dist-info/RECORD", b""),
                ("other-2.0.dist-info/RECORD", b""),
            ],
        );
        let error = install_wheel(
            &doubled,
            &site,
            &bin,
            "3.12",
            &bin.join("python"),
            &mut BTreeMap::new(),
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            error.to_string(),
            "wheel has multiple .dist-info dirs: demo-1.0.dist-info, other-2.0.dist-info"
        );
    }

    #[test]
    fn rejects_unsupported_data_scheme() {
        let temp = TempDir::new();
        let site = temp.path().join("lib/python3.12/site-packages");
        let bin = temp.path().join("bin");
        fs::create_dir_all(&site).unwrap();
        fs::create_dir_all(&bin).unwrap();
        let wheel = temp.path().join("demo-1.0.whl");
        write_wheel(
            &wheel,
            &[
                ("demo-1.0.dist-info/RECORD", b""),
                ("demo-1.0.data/scriptz/tool", b"nope"),
            ],
        );

        let error = install_wheel(
            &wheel,
            &site,
            &bin,
            "3.12",
            &bin.join("python"),
            &mut BTreeMap::new(),
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            error.to_string(),
            "unsupported wheel .data scheme 'scriptz' in demo-1.0.data/scriptz/tool"
        );
    }

    #[test]
    fn reports_unclaimed_and_same_wheel_collisions() {
        let temp = TempDir::new();
        let wheel = temp.path().join("demo-1.0.whl");
        write_wheel(
            &wheel,
            &[
                ("demo-1.0.dist-info/RECORD", b""),
                (
                    "demo-1.0.dist-info/entry_points.txt",
                    b"[console_scripts]\ntool = demo:main\n",
                ),
                ("demo/__init__.py", b"value = 1\n"),
            ],
        );

        // Each phase gets a pristine environment: install_wheel writes
        // entries in archive order and stops at the first collision.
        let fresh = |tag: &str| {
            let site = temp.path().join(tag).join("lib/python3.12/site-packages");
            let bin = temp.path().join(tag).join("bin");
            fs::create_dir_all(&site).unwrap();
            fs::create_dir_all(&bin).unwrap();
            (site, bin)
        };

        // A file nobody in `installed` claims is never superseded.
        let (site, bin) = fresh("unclaimed");
        fs::create_dir_all(site.join("demo")).unwrap();
        fs::write(site.join("demo/__init__.py"), b"squatter\n").unwrap();
        let error = install_wheel(
            &wheel,
            &site,
            &bin,
            "3.12",
            &bin.join("python"),
            &mut BTreeMap::new(),
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(
            error
                .to_string()
                .contains("already exists (from an earlier wheel or entry)"),
            "{error}"
        );
        assert_eq!(
            fs::read_to_string(site.join("demo/__init__.py")).unwrap(),
            "squatter\n"
        );

        // The same wheel installing a path twice is an error, not an overwrite.
        let (site, bin) = fresh("same-wheel");
        fs::create_dir_all(site.join("demo")).unwrap();
        fs::write(site.join("demo/__init__.py"), b"squatter\n").unwrap();
        let mut installed = BTreeMap::new();
        installed.insert(
            site.join("demo/__init__.py"),
            "demo-1.0.dist-info".to_string(),
        );
        let error = install_wheel(
            &wheel,
            &site,
            &bin,
            "3.12",
            &bin.join("python"),
            &mut installed,
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(
            error
                .to_string()
                .contains("already exists in wheel demo-1.0.dist-info"),
            "{error}"
        );

        // Console-script launchers use their own collision message.
        let (site, bin) = fresh("script");
        fs::write(bin.join("tool"), b"squatter\n").unwrap();
        let error = install_wheel(
            &wheel,
            &site,
            &bin,
            "3.12",
            &bin.join("python"),
            &mut BTreeMap::new(),
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            error.to_string(),
            format!("console-script collision: {}", bin.join("tool").display())
        );
    }
}

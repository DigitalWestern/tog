//! Wheel installer: unpack a .whl into a target environment, PEP 427 style.
//!
//! IMPLEMENTATION CONTRACT (see install_wheel below) — being implemented.

use std::fs;
use std::io;
use std::io::Read;
use std::path::Path;

use zip::ZipArchive;

/// Install one wheel into an environment being assembled (PEP 427,
/// pragmatic subset). Routes `{name}.data/{purelib,platlib,scripts,data}`,
/// rewrites `#!python` shebangs, generates console/gui-script launchers,
/// guards against zip-slip/symlinks, and errors on file collisions.
/// Known v0 gaps: RECORD is left as shipped (not verified or rewritten);
/// `headers` .data scheme is rejected rather than implemented.
pub fn install_wheel(
    wheel_path: &Path,
    site_packages: &Path,
    bin_dir: &Path,
    python_exe: &Path,
) -> io::Result<()> {
    let file = fs::File::open(wheel_path)?;
    let mut archive = ZipArchive::new(file).map_err(zip_error)?;

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

    if dist_info.is_none() {
        return Err(invalid_data(format!(
            "{} contains no .dist-info directory; not a wheel",
            wheel_path.display()
        )));
    }
    let data_prefix = dist_info
        .as_deref()
        .map(|name| format!("{}.data/", name.strip_suffix(".dist-info").unwrap_or(name)));
    let entry_points = dist_info.as_deref().and_then(|name| {
        archive
            .by_name(&format!("{name}/entry_points.txt"))
            .ok()
            .map(|mut entry| {
                let mut contents = String::new();
                entry.read_to_string(&mut contents).map(|_| contents)
            })
    });
    let entry_points = match entry_points {
        Some(Ok(contents)) => Some(contents),
        Some(Err(error)) => return Err(error),
        None => None,
    };

    let env_root = bin_dir.parent().ok_or_else(|| {
        invalid_data(format!(
            "bin directory has no environment root: {}",
            bin_dir.display()
        ))
    })?;
    let mut directory_modes = Vec::new();

    const MAX_UNPACKED_BYTES: u64 = 4 * 1024 * 1024 * 1024; // 4 GiB aggregate
    let mut total_written: u64 = 0;

    for index in 0..archive.len() {
        let mut entry = archive.by_index(index).map_err(zip_error)?;
        let name = entry.name().to_string();
        let (base, relative, executable) = if let Some(prefix) = data_prefix.as_deref() {
            if let Some(rest) = name.strip_prefix(prefix) {
                let Some((kind, relative)) = rest.split_once('/') else {
                    continue;
                };
                match kind {
                    "purelib" | "platlib" => (site_packages, relative, false),
                    "scripts" => (bin_dir, relative, true),
                    "data" => (env_root, relative, false),
                    other => {
                        return Err(invalid_data(format!(
                            "unsupported wheel .data scheme '{other}' in {name}"
                        )))
                    }
                }
            } else {
                (site_packages, name.as_str(), false)
            }
        } else {
            (site_packages, name.as_str(), false)
        };

        let destination = base.join(relative);
        if entry.is_dir() {
            fs::create_dir_all(&destination)?;
            if let Some(mode) = entry.unix_mode() {
                directory_modes.push((destination, mode & 0o777));
            }
            continue;
        }

        if destination.symlink_metadata().is_ok() {
            return Err(invalid_data(format!(
                "file collision: {} already exists (from an earlier wheel or entry)",
                destination.display()
            )));
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
        if executable {
            // Scripts are small; buffer them for shebang rewriting.
            let mut contents = Vec::new();
            entry.read_to_end(&mut contents)?;
            if contents.starts_with(b"#!python") {
                contents = rewrite_shebang(&contents, python_exe);
            }
            fs::write(&destination, contents)?;
        } else {
            let mut out = fs::File::create(&destination)?;
            io::copy(&mut entry, &mut out)?;
        }
        let mode = if executable {
            Some(0o755)
        } else {
            entry.unix_mode().map(|mode| (mode & 0o777).max(0o644))
        };
        if let Some(mode) = mode {
            set_mode(&destination, mode)?;
        }
    }

    for (directory, mode) in directory_modes {
        set_mode(&directory, mode)?;
    }

    if let Some(entry_points) = entry_points {
        for (name, module, attr) in parse_entry_points(&entry_points)? {
            let attr0 = attr.split('.').next().unwrap();
            let launcher = format!(
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
            );
            let destination = bin_dir.join(name);
            if destination.symlink_metadata().is_ok() {
                return Err(invalid_data(format!(
                    "console-script collision: {}",
                    destination.display()
                )));
            }
            fs::create_dir_all(bin_dir)?;
            fs::write(&destination, launcher)?;
            set_mode(&destination, 0o755)?;
        }
    }

    Ok(())
}

fn zip_error(error: zip::result::ZipError) -> io::Error {
    invalid_data(error.to_string())
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn validate_entry_name(name: &str) -> io::Result<()> {
    if name.starts_with('/') || name.split(['/', '\\']).any(|component| component == "..") {
        return Err(invalid_data(format!("unsafe zip entry: {name}")));
    }
    Ok(())
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
                ("demo-1.0.data/scripts/raw.bin", &[0, 1, 255]),
                ("demo-1.0.data/data/share/demo.txt", b"shared\n"),
            ],
        );

        install_wheel(&wheel, &site, &bin, &python).unwrap();

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

        let error = install_wheel(&wheel, &site, &bin, &bin.join("python")).unwrap_err();
        assert!(error.to_string().contains("../escaped.txt"));
        assert!(!temp.path().join("escaped.txt").exists());
    }
}

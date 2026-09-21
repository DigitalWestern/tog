//! Declarative toolchain inputs: what version each ecosystem asked for,
//! read from text files only.
//!
//! Every reader here takes file bytes and returns the canonical request it
//! found. None of them starts a program, reads the environment, or touches
//! the filesystem. That keeps frozen validation free of project code: it can
//! read inputs and compare them without planning dependencies.
//!
//! Discovery walks from a held project root so a symlinked input or ancestor
//! fails closed instead of being read through. A project whose only version
//! statement is computed (a `setup.py` or `mix.exs` with no declarative file)
//! has no row with a value; the caller reports which file to add.

use crate::kernel::fsroot::ProjectRoot;
use sha2::{Digest as _, Sha256};
use std::io;
use std::path::{Path, PathBuf};

/// One consulted source, in precedence order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InputRow {
    /// Project-relative path that was consulted.
    pub path: PathBuf,
    /// The field inside the file that carries the request.
    pub field: String,
    /// The parsed request, when the file held one.
    pub value: Option<String>,
    /// True when the file had no request at `field`.
    pub absent: bool,
    /// Hex sha256 over the whole file bytes, when the file exists.
    pub sha256: Option<String>,
}

impl InputRow {
    fn present(path: &str, field: &str, value: String, bytes: &[u8]) -> Self {
        Self {
            path: PathBuf::from(path),
            field: field.to_string(),
            value: Some(value),
            absent: false,
            sha256: Some(hex::encode(Sha256::digest(bytes))),
        }
    }

    fn present_without_value(path: &str, field: &str, bytes: &[u8]) -> Self {
        Self {
            path: PathBuf::from(path),
            field: field.to_string(),
            value: None,
            absent: true,
            sha256: Some(hex::encode(Sha256::digest(bytes))),
        }
    }

    fn missing(path: &str, field: &str) -> Self {
        Self {
            path: PathBuf::from(path),
            field: field.to_string(),
            value: None,
            absent: true,
            sha256: None,
        }
    }
}

/// First non-blank, non-comment line, trimmed.
fn first_line(bytes: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(bytes).ok()?;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        return Some(line.to_string());
    }
    None
}

/// `.python-version`: a version like `3.12.1`.
pub fn read_python_version(bytes: &[u8]) -> Option<String> {
    first_line(bytes)
}

/// `.node-version`: a version like `24.20.0`, with an optional leading `v`.
pub fn read_node_version(bytes: &[u8]) -> Option<String> {
    first_line(bytes).map(|line| line.strip_prefix('v').unwrap_or(&line).to_string())
}

/// `.ruby-version`: `3.3.0` or `ruby-3.3.0`.
pub fn read_ruby_version(bytes: &[u8]) -> Option<String> {
    first_line(bytes).map(|line| {
        line.strip_prefix("ruby-")
            .unwrap_or(&line)
            .trim()
            .to_string()
    })
}

/// One `.tool-versions` line per tool: `python 3.12.1`, `nodejs 24.20.0`,
/// `ruby 3.3.0`, `golang 1.22.0`, `rust 1.96.1`, `elixir 1.17`, `dotnet 8.0.100`.
fn tool_versions_field(bytes: &[u8], tool: &str) -> Option<String> {
    let text = std::str::from_utf8(bytes).ok()?;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let name = parts.next()?;
        let version = parts.next()?;
        if name == tool {
            return Some(version.to_string());
        }
    }
    None
}

pub fn read_tool_versions_python(bytes: &[u8]) -> Option<String> {
    tool_versions_field(bytes, "python")
}

pub fn read_tool_versions_node(bytes: &[u8]) -> Option<String> {
    tool_versions_field(bytes, "nodejs").or_else(|| tool_versions_field(bytes, "node"))
}

pub fn read_tool_versions_ruby(bytes: &[u8]) -> Option<String> {
    tool_versions_field(bytes, "ruby")
}

pub fn read_tool_versions_go(bytes: &[u8]) -> Option<String> {
    tool_versions_field(bytes, "golang").or_else(|| tool_versions_field(bytes, "go"))
}

pub fn read_tool_versions_rust(bytes: &[u8]) -> Option<String> {
    tool_versions_field(bytes, "rust")
}

pub fn read_tool_versions_elixir(bytes: &[u8]) -> Option<String> {
    tool_versions_field(bytes, "elixir")
}

pub fn read_tool_versions_dotnet(bytes: &[u8]) -> Option<String> {
    tool_versions_field(bytes, "dotnet")
}

/// `global.json`: `{"sdk": {"version": "8.0.100"}}`.
pub fn read_global_json(bytes: &[u8]) -> Option<String> {
    let value: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    value
        .get("sdk")?
        .get("version")?
        .as_str()
        .map(str::to_string)
}

/// `rust-toolchain.toml`: `[toolchain] channel = "1.96.1"`.
pub fn read_rust_toolchain(bytes: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(bytes).ok()?;
    let value: toml::Value = toml::from_str(text).ok()?;
    value
        .get("toolchain")?
        .get("channel")?
        .as_str()
        .map(str::to_string)
}

/// `go.mod`: the `go 1.22.0` directive, or a `toolchain go1.22.0` line.
pub fn read_go_mod(bytes: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(bytes).ok()?;
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("go ") {
            let version = rest.split_whitespace().next()?;
            if !version.is_empty() {
                return Some(version.to_string());
            }
        }
        if let Some(rest) = line.strip_prefix("toolchain ") {
            let version = rest.split_whitespace().next()?.strip_prefix("go")?;
            if !version.is_empty() {
                return Some(version.to_string());
            }
        }
    }
    None
}

/// Message for a project whose only version statement is computed: it names
/// the declarative file to add instead of guessing from the evaluator.
pub fn computed_only_message(ecosystem: &str) -> String {
    let file = match ecosystem {
        "python" => ".python-version",
        "node" => ".node-version",
        "ruby" => ".ruby-version",
        "go" => "go.mod (`go` directive)",
        "rust" => "rust-toolchain.toml",
        "elixir" => ".tool-versions",
        "dotnet" => "global.json",
        _ => ".tool-versions",
    };
    format!(
        "{ecosystem}: version is only stated by computed project code; add a declarative {file} so the toolchain lock can record it"
    )
}

fn row_for(
    root: &ProjectRoot,
    path: &str,
    field: &str,
    parse: impl Fn(&[u8]) -> Option<String>,
) -> io::Result<InputRow> {
    match root.read_file(Path::new(path))? {
        None => Ok(InputRow::missing(path, field)),
        Some(bytes) => match parse(&bytes) {
            Some(value) => Ok(InputRow::present(path, field, value, &bytes)),
            None => Ok(InputRow::present_without_value(path, field, &bytes)),
        },
    }
}

/// Every consulted source for one ecosystem, in precedence order. Each row
/// records presence and value separately: a missing file, a present file
/// without the field, and a field found each have one spelling.
pub fn discover(root: &ProjectRoot, ecosystem: &str) -> io::Result<Vec<InputRow>> {
    let rows = match ecosystem {
        "python" => vec![
            row_for(root, ".python-version", "version", read_python_version)?,
            row_for(root, ".tool-versions", "python", read_tool_versions_python)?,
        ],
        "node" => vec![
            row_for(root, ".node-version", "version", read_node_version)?,
            row_for(root, ".tool-versions", "nodejs", read_tool_versions_node)?,
            row_for(root, "package.json", "engines.node", |_| None)?,
        ],
        "ruby" => vec![
            row_for(root, ".ruby-version", "version", read_ruby_version)?,
            row_for(root, ".tool-versions", "ruby", read_tool_versions_ruby)?,
        ],
        "go" => vec![
            row_for(root, "go.mod", "go", read_go_mod)?,
            row_for(root, ".tool-versions", "golang", read_tool_versions_go)?,
        ],
        "rust" => vec![
            row_for(
                root,
                "rust-toolchain.toml",
                "toolchain.channel",
                read_rust_toolchain,
            )?,
            row_for(root, ".tool-versions", "rust", read_tool_versions_rust)?,
        ],
        "elixir" => vec![row_for(
            root,
            ".tool-versions",
            "elixir",
            read_tool_versions_elixir,
        )?],
        "dotnet" => vec![
            row_for(root, "global.json", "sdk.version", read_global_json)?,
            row_for(root, ".tool-versions", "dotnet", read_tool_versions_dotnet)?,
        ],
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unknown ecosystem '{ecosystem}'"),
            ))
        }
    };
    Ok(rows)
}

/// All seven ecosystems, each with its consulted rows.
pub fn discover_all(root: &ProjectRoot) -> io::Result<Vec<(String, Vec<InputRow>)>> {
    let ecosystems = ["python", "node", "ruby", "go", "rust", "elixir", "dotnet"];
    let mut out = Vec::with_capacity(ecosystems.len());
    for ecosystem in ecosystems {
        out.push((ecosystem.to_string(), discover(root, ecosystem)?));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::testutil::TempDir;

    fn missing_and_present_shapes() {
        let temp = TempDir::new();
        let dir = temp.0.join("proj");
        std::fs::create_dir_all(&dir).unwrap();
        let root = ProjectRoot::open(&dir).unwrap();
        let rows = discover(&root, "python").unwrap();
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|row| row.absent && row.sha256.is_none()));
        std::fs::write(dir.join(".python-version"), "3.12.1\n").unwrap();
        let rows = discover(&root, "python").unwrap();
        assert_eq!(rows[0].value.as_deref(), Some("3.12.1"));
        assert_eq!(rows[0].absent, false);
        assert!(rows[0].sha256.is_some());
    }

    #[test]
    fn python_reader_finds_a_version() {
        assert_eq!(read_python_version(b"3.12.1\n"), Some("3.12.1".into()));
        assert_eq!(
            read_python_version(b"# comment\n\n3.12\n"),
            Some("3.12".into())
        );
        assert_eq!(read_python_version(b""), None);
        missing_and_present_shapes();
    }

    #[test]
    fn node_reader_strips_a_leading_v() {
        assert_eq!(read_node_version(b"24.20.0\n"), Some("24.20.0".into()));
        assert_eq!(read_node_version(b"v24.20.0\n"), Some("24.20.0".into()));
        assert_eq!(read_node_version(b""), None);
    }

    #[test]
    fn ruby_reader_handles_ruby_prefix() {
        assert_eq!(read_ruby_version(b"3.3.0\n"), Some("3.3.0".into()));
        assert_eq!(read_ruby_version(b"ruby-3.3.0\n"), Some("3.3.0".into()));
        assert_eq!(read_ruby_version(b""), None);
    }

    #[test]
    fn tool_versions_reader_finds_each_tool() {
        let bytes = b"python 3.12.1\nnodejs 24.20.0\nruby 3.3.0\ngolang 1.22.0\nrust 1.96.1\nelixir 1.17\ndotnet 8.0.100\n";
        assert_eq!(read_tool_versions_python(bytes), Some("3.12.1".into()));
        assert_eq!(read_tool_versions_node(bytes), Some("24.20.0".into()));
        assert_eq!(read_tool_versions_ruby(bytes), Some("3.3.0".into()));
        assert_eq!(read_tool_versions_go(bytes), Some("1.22.0".into()));
        assert_eq!(read_tool_versions_rust(bytes), Some("1.96.1".into()));
        assert_eq!(read_tool_versions_elixir(bytes), Some("1.17".into()));
        assert_eq!(read_tool_versions_dotnet(bytes), Some("8.0.100".into()));
        assert_eq!(read_tool_versions_python(b"ruby 3.3.0\n"), None);
    }

    #[test]
    fn global_json_reader_finds_sdk_version() {
        let bytes = br#"{"sdk": {"version": "8.0.100"}}"#;
        assert_eq!(read_global_json(bytes), Some("8.0.100".into()));
        assert_eq!(read_global_json(b"{}"), None);
        assert_eq!(read_global_json(b"not json"), None);
    }

    #[test]
    fn rust_toolchain_reader_finds_channel() {
        let bytes = b"[toolchain]\nchannel = \"1.96.1\"\n";
        assert_eq!(read_rust_toolchain(bytes), Some("1.96.1".into()));
        assert_eq!(read_rust_toolchain(b"[toolchain]\n"), None);
        assert_eq!(read_rust_toolchain(b"not toml ["), None);
    }

    #[test]
    fn go_mod_reader_finds_go_directive() {
        assert_eq!(
            read_go_mod(b"module example.com/m\n\ngo 1.22.0\n"),
            Some("1.22.0".into())
        );
        assert_eq!(
            read_go_mod(b"module m\ntoolchain go1.22.0\n"),
            Some("1.22.0".into())
        );
        assert_eq!(read_go_mod(b"module m\n"), None);
    }

    #[test]
    fn readers_start_no_programs() {
        // The readers take bytes and return strings. If one of them ever
        // shells out, this guard names it: the module must not mention a
        // process API at all.
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/kernel/toolchain/input.rs");
        let text = std::fs::read_to_string(&path).unwrap();
        let non_test = match text.find("#[cfg(test)]") {
            Some(index) => &text[..index],
            None => &text,
        };
        for marker in [
            "std::process",
            "Command::new",
            "Command(",
            ".spawn()",
            ".status()",
            ".output()",
            "run_command",
        ] {
            assert!(
                !non_test.contains(marker),
                "reader mentions process API {marker:?}"
            );
        }
        // And each ecosystem has its own parsing test above, so a reader
        // that delegates to a tool would have nowhere to hide its output.
        for ecosystem in ["python", "node", "ruby", "go", "rust", "elixir", "dotnet"] {
            assert!(
                text.contains(&format!("fn {ecosystem}_reader"))
                    || text.contains(&format!("read_tool_versions_{ecosystem}"))
                    || text.contains(ecosystem),
                "no reader test names {ecosystem}"
            );
        }
    }

    #[test]
    fn discovery_records_absence_instead_of_omitting() {
        let temp = TempDir::new();
        let dir = temp.0.join("proj");
        std::fs::create_dir_all(&dir).unwrap();
        let root = ProjectRoot::open(&dir).unwrap();
        let rows = discover(&root, "node").unwrap();
        assert_eq!(rows.len(), 3);
        assert!(rows.iter().all(|row| row.absent));
        assert!(rows.iter().all(|row| row.sha256.is_none()));
        std::fs::write(dir.join("package.json"), "{}\n").unwrap();
        let rows = discover(&root, "node").unwrap();
        let manifest = rows
            .iter()
            .find(|row| row.path.ends_with("package.json"))
            .unwrap();
        assert!(manifest.absent);
        assert!(manifest.sha256.is_some());
    }

    #[test]
    fn computed_only_message_names_a_file() {
        assert!(computed_only_message("python").contains(".python-version"));
        assert!(computed_only_message("node").contains(".node-version"));
        assert!(computed_only_message("dotnet").contains("global.json"));
    }
}

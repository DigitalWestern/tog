//! Declarative toolchain inputs: what version each ecosystem asked for,
//! read from text files only.
//!
//! Every reader here takes file bytes and returns the canonical request it
//! found. None of them starts a program, reads the environment, or touches
//! the filesystem. That keeps frozen validation free of project code: it can
//! read inputs and compare them without planning dependencies.
//!
//! Discovery walks from a held project root so a symlinked input or ancestor
//! fails closed instead of being read through. The consulted rows per
//! ecosystem are the sources its own native tools honor, in that tool's
//! precedence order, and only the declarative ones: a project whose only
//! version statement is computed (a `setup.py`, `mix.exs`, or Gemfile
//! directive) has no row with a value; the caller reports which file to add.

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
    text.lines()
        .map(str::trim)
        .find(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_string)
}

/// A TOML document, or `None` when the bytes are not valid TOML.
fn toml_document(bytes: &[u8]) -> Option<toml::Value> {
    let text = std::str::from_utf8(bytes).ok()?;
    toml::from_str(text).ok()
}

/// `.python-version`: a version like `3.12.1`. An explicit CPython prefix
/// (`python3.12`, `cpython-3.12`, `cpython@3.12`, in any casing) is a
/// spelling of the same request, so the recorded value is the canonical
/// `X.Y[.Z]`. Anything else is kept verbatim for the caller to refuse.
pub fn read_python_version(bytes: &[u8]) -> Option<String> {
    let line = first_line(bytes)?;
    let lower = line.to_ascii_lowercase();
    for prefix in ["cpython-", "cpython@", "python"] {
        let Some(rest) = lower.strip_prefix(prefix) else {
            continue;
        };
        if rest.starts_with(|c: char| c.is_ascii_digit()) {
            return Some(line[prefix.len()..].to_string());
        }
    }
    Some(line)
}

fn malformed(message: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("pyproject.toml: {message}"),
    )
}

/// `pyproject.toml`: `[project] requires-python = ">=3.12"`. A value that
/// is present but not a string is refused, as Python's own input check
/// refuses it, rather than recorded as absent: a lock must not read a
/// malformed request as no request.
pub fn read_pyproject_requires_python(bytes: &[u8]) -> io::Result<Option<String>> {
    let Some(value) = toml_document(bytes)
        .as_ref()
        .and_then(|document| document.get("project")?.get("requires-python").cloned())
    else {
        return Ok(None);
    };
    match value {
        toml::Value::String(text) => Ok(Some(text)),
        _ => Err(malformed("requires-python must be a string")),
    }
}

/// `pyproject.toml`: `[tool.poetry.dependencies] python = "^3.9"`, or the
/// table spelling `python = { version = "^3.9" }`. Any other shape is
/// refused, as Python's own input check refuses it.
pub fn read_pyproject_poetry_python(bytes: &[u8]) -> io::Result<Option<String>> {
    let Some(python) = toml_document(bytes).as_ref().and_then(|document| {
        document
            .get("tool")?
            .get("poetry")?
            .get("dependencies")?
            .get("python")
            .cloned()
    }) else {
        return Ok(None);
    };
    match python {
        toml::Value::String(text) => Ok(Some(text)),
        toml::Value::Table(table) => match table.get("version") {
            Some(toml::Value::String(text)) => Ok(Some(text.clone())),
            _ => Err(malformed(
                "[tool.poetry.dependencies].python table needs a string version",
            )),
        },
        _ => Err(malformed(
            "[tool.poetry.dependencies].python must be a string or table",
        )),
    }
}

/// `.node-version`: a version like `24.20.0`, with an optional leading `v`.
pub fn read_node_version(bytes: &[u8]) -> Option<String> {
    first_line(bytes).map(|line| line.strip_prefix('v').unwrap_or(&line).to_string())
}

/// `package.json`: `{"engines": {"node": ">=24"}}`.
pub fn read_package_json_engines_node(bytes: &[u8]) -> Option<String> {
    let value: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    value
        .get("engines")?
        .get("node")?
        .as_str()
        .map(str::to_string)
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

/// One `.tool-versions` line per tool: `ruby 3.3.0`, `erlang 27.0`,
/// `elixir 1.17.0`. A line with a name and no version is skipped, not a
/// reason to stop reading.
pub fn read_tool_versions(bytes: &[u8], tool: &str) -> Option<String> {
    let text = std::str::from_utf8(bytes).ok()?;
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        let mut parts = line.split_whitespace();
        let (Some(name), Some(version)) = (parts.next(), parts.next()) else {
            continue;
        };
        if name == tool {
            return Some(version.to_string());
        }
    }
    None
}

/// `global.json`: `{"sdk": {"version": "8.0.100"}}`.
pub fn read_global_json(bytes: &[u8]) -> Option<String> {
    global_json_sdk_field(bytes, "version")
}

/// `global.json`: `{"sdk": {"rollForward": "disable"}}`. Recorded beside
/// the version because it decides whether that version is exact.
pub fn read_global_json_roll_forward(bytes: &[u8]) -> Option<String> {
    global_json_sdk_field(bytes, "rollForward")
}

fn global_json_sdk_field(bytes: &[u8], field: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    value.get("sdk")?.get(field)?.as_str().map(str::to_string)
}

/// `rust-toolchain.toml`: `[toolchain] channel = "1.96.1"`.
pub fn read_rust_toolchain(bytes: &[u8]) -> Option<String> {
    toml_document(bytes)?
        .get("toolchain")?
        .get("channel")?
        .as_str()
        .map(str::to_string)
}

/// Legacy `rust-toolchain`: a bare channel on the first line, or the same
/// TOML document rustup accepts at that name. A document with a
/// `[toolchain]` table is read as TOML only, so a table without a channel
/// yields no value instead of the literal header line.
pub fn read_rust_toolchain_legacy(bytes: &[u8]) -> Option<String> {
    match toml_document(bytes) {
        Some(document) if document.get("toolchain").is_some() => document
            .get("toolchain")?
            .get("channel")?
            .as_str()
            .map(str::to_string),
        _ => first_line(bytes),
    }
}

/// `go.mod`: the `go 1.22.0` directive, the module's minimum.
pub fn read_go_mod(bytes: &[u8]) -> Option<String> {
    go_mod_directive(bytes, "go")
}

/// `go.mod`: a `toolchain go1.22.0` line, the exact request. `toolchain
/// default` means the same as no line, so it yields no value.
pub fn read_go_mod_toolchain(bytes: &[u8]) -> Option<String> {
    let value = go_mod_directive(bytes, "toolchain")?;
    if value == "default" {
        return None;
    }
    Some(value.strip_prefix("go").unwrap_or(&value).to_string())
}

fn go_mod_directive(bytes: &[u8], directive: &str) -> Option<String> {
    let text = std::str::from_utf8(bytes).ok()?;
    for line in text.lines() {
        let line = line.split("//").next().unwrap_or("").trim();
        let mut parts = line.split_whitespace();
        let (Some(name), Some(value)) = (parts.next(), parts.next()) else {
            continue;
        };
        if name == directive {
            return Some(value.to_string());
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
    checked_row_for(root, path, field, |bytes| Ok(parse(bytes)))
}

/// `row_for` for a reader that can refuse a malformed value outright.
fn checked_row_for(
    root: &ProjectRoot,
    path: &str,
    field: &str,
    parse: impl Fn(&[u8]) -> io::Result<Option<String>>,
) -> io::Result<InputRow> {
    match root.read_file(Path::new(path))? {
        None => Ok(InputRow::missing(path, field)),
        Some(bytes) => match parse(&bytes)? {
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
            checked_row_for(
                root,
                "pyproject.toml",
                "project.requires-python",
                read_pyproject_requires_python,
            )?,
            checked_row_for(
                root,
                "pyproject.toml",
                "tool.poetry.dependencies.python",
                read_pyproject_poetry_python,
            )?,
        ],
        "node" => vec![
            row_for(root, ".node-version", "version", read_node_version)?,
            row_for(
                root,
                "package.json",
                "engines.node",
                read_package_json_engines_node,
            )?,
        ],
        "ruby" => vec![
            row_for(root, ".ruby-version", "version", read_ruby_version)?,
            row_for(root, ".tool-versions", "ruby", |bytes| {
                read_tool_versions(bytes, "ruby")
            })?,
        ],
        "go" => vec![
            row_for(root, "go.mod", "go", read_go_mod)?,
            row_for(root, "go.mod", "toolchain", read_go_mod_toolchain)?,
        ],
        "rust" => vec![
            row_for(
                root,
                "rust-toolchain",
                "toolchain.channel",
                read_rust_toolchain_legacy,
            )?,
            row_for(
                root,
                "rust-toolchain.toml",
                "toolchain.channel",
                read_rust_toolchain,
            )?,
        ],
        "elixir" => vec![
            row_for(root, ".tool-versions", "erlang", |bytes| {
                read_tool_versions(bytes, "erlang")
            })?,
            row_for(root, ".tool-versions", "elixir", |bytes| {
                read_tool_versions(bytes, "elixir")
            })?,
        ],
        "dotnet" => vec![
            row_for(root, "global.json", "sdk.version", read_global_json)?,
            row_for(
                root,
                "global.json",
                "sdk.rollForward",
                read_global_json_roll_forward,
            )?,
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

/// Every ecosystem this module knows, in lock order.
pub const ECOSYSTEMS: [&str; 7] = ["python", "node", "ruby", "go", "rust", "elixir", "dotnet"];

/// The named ecosystems, each with its consulted rows.
pub fn discover_many<'a>(
    root: &ProjectRoot,
    ecosystems: impl IntoIterator<Item = &'a str>,
) -> io::Result<Vec<(String, Vec<InputRow>)>> {
    let mut out = Vec::new();
    for ecosystem in ecosystems {
        out.push((ecosystem.to_string(), discover(root, ecosystem)?));
    }
    Ok(out)
}

/// All seven ecosystems, each with its consulted rows.
pub fn discover_all(root: &ProjectRoot) -> io::Result<Vec<(String, Vec<InputRow>)>> {
    discover_many(root, ECOSYSTEMS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::testutil::TempDir;

    fn project() -> (TempDir, ProjectRoot) {
        let temp = TempDir::new();
        let dir = temp.0.join("proj");
        std::fs::create_dir_all(&dir).unwrap();
        let root = ProjectRoot::open(&dir).unwrap();
        (temp, root)
    }

    #[test]
    fn missing_and_present_shapes() {
        let (temp, root) = project();
        let dir = temp.0.join("proj");
        let rows = discover(&root, "python").unwrap();
        assert_eq!(rows.len(), 3);
        assert!(rows.iter().all(|row| row.absent && row.sha256.is_none()));
        std::fs::write(dir.join(".python-version"), "3.12.1\n").unwrap();
        let rows = discover(&root, "python").unwrap();
        assert_eq!(rows[0].value.as_deref(), Some("3.12.1"));
        assert!(!rows[0].absent);
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
        for spelling in [
            "python3.12",
            "Python3.12",
            "cpython-3.12",
            "CPython-3.12",
            "cpython@3.12",
            "CPYTHON@3.12",
        ] {
            assert_eq!(
                read_python_version(format!("{spelling}\n").as_bytes()),
                Some("3.12".into()),
                "{spelling}"
            );
        }
        // Anything that is not a CPython prefix is kept verbatim so the
        // caller can refuse it by name.
        assert_eq!(read_python_version(b"pypy3.10\n"), Some("pypy3.10".into()));
        assert_eq!(read_python_version(b"python\n"), Some("python".into()));
    }

    #[test]
    fn python_pyproject_readers_find_each_field() {
        let bytes = b"[project]\nrequires-python = \">=3.12\"\n\n[tool.poetry.dependencies]\npython = \"^3.9\"\n";
        let read = |bytes: &[u8]| read_pyproject_requires_python(bytes).unwrap();
        let poetry = |bytes: &[u8]| read_pyproject_poetry_python(bytes).unwrap();
        assert_eq!(read(bytes), Some(">=3.12".into()));
        assert_eq!(poetry(bytes), Some("^3.9".into()));
        let table = b"[tool.poetry.dependencies]\npython = { version = \"^3.9\" }\n";
        assert_eq!(poetry(table), Some("^3.9".into()));
        assert_eq!(read(b"[project]\n"), None);
        assert_eq!(poetry(b"[project]\n"), None);
        assert_eq!(read(b"not toml ["), None);
    }

    /// A field that is there but malformed is refused in the words Python's
    /// input check uses, never recorded as absent.
    #[test]
    fn python_pyproject_readers_refuse_a_malformed_field() {
        let error =
            read_pyproject_requires_python(b"[project]\nrequires-python = 3\n").unwrap_err();
        assert!(
            error
                .to_string()
                .contains("requires-python must be a string"),
            "{error}"
        );
        for bytes in [
            &b"[tool.poetry.dependencies]\npython = 3\n"[..],
            b"[tool.poetry.dependencies]\npython = { version = 3 }\n",
            b"[tool.poetry.dependencies]\npython = {}\n",
        ] {
            assert!(read_pyproject_poetry_python(bytes).is_err());
        }
    }

    #[test]
    fn node_reader_strips_a_leading_v() {
        assert_eq!(read_node_version(b"24.20.0\n"), Some("24.20.0".into()));
        assert_eq!(read_node_version(b"v24.20.0\n"), Some("24.20.0".into()));
        assert_eq!(read_node_version(b""), None);
    }

    #[test]
    fn node_engines_reader_finds_the_range() {
        let bytes = br#"{"name": "x", "engines": {"node": ">=24.20.0"}}"#;
        assert_eq!(
            read_package_json_engines_node(bytes),
            Some(">=24.20.0".into())
        );
        assert_eq!(read_package_json_engines_node(b"{}"), None);
        assert_eq!(read_package_json_engines_node(b"not json"), None);
    }

    #[test]
    fn ruby_reader_handles_ruby_prefix() {
        assert_eq!(read_ruby_version(b"3.3.0\n"), Some("3.3.0".into()));
        assert_eq!(read_ruby_version(b"ruby-3.3.0\n"), Some("3.3.0".into()));
        assert_eq!(read_ruby_version(b""), None);
    }

    #[test]
    fn tool_versions_reader_finds_each_tool() {
        let bytes = b"# pinned\npython 3.12.1 2.7.18\nruby 3.3.0 # trailing\nerlang 27.0\nelixir 1.17.0-otp-27\n";
        assert_eq!(read_tool_versions(bytes, "python"), Some("3.12.1".into()));
        assert_eq!(read_tool_versions(bytes, "ruby"), Some("3.3.0".into()));
        assert_eq!(read_tool_versions(bytes, "erlang"), Some("27.0".into()));
        assert_eq!(
            read_tool_versions(bytes, "elixir"),
            Some("1.17.0-otp-27".into())
        );
        assert_eq!(read_tool_versions(bytes, "nodejs"), None);
        // A malformed line earlier in the file does not hide a later match.
        assert_eq!(
            read_tool_versions(b"ruby\nelixir 1.17\n", "elixir"),
            Some("1.17".into())
        );
    }

    #[test]
    fn global_json_reader_finds_sdk_version() {
        let bytes = br#"{"sdk": {"version": "8.0.100", "rollForward": "disable"}}"#;
        assert_eq!(read_global_json(bytes), Some("8.0.100".into()));
        assert_eq!(read_global_json_roll_forward(bytes), Some("disable".into()));
        assert_eq!(read_global_json(b"{}"), None);
        assert_eq!(read_global_json_roll_forward(b"{\"sdk\": {}}"), None);
        assert_eq!(read_global_json(b"not json"), None);
    }

    #[test]
    fn rust_toolchain_readers_find_channel() {
        let bytes = b"[toolchain]\nchannel = \"1.96.1\"\n";
        assert_eq!(read_rust_toolchain(bytes), Some("1.96.1".into()));
        assert_eq!(read_rust_toolchain(b"[toolchain]\n"), None);
        assert_eq!(read_rust_toolchain(b"not toml ["), None);
        assert_eq!(read_rust_toolchain_legacy(bytes), Some("1.96.1".into()));
        assert_eq!(
            read_rust_toolchain_legacy(b"1.96.1\n"),
            Some("1.96.1".into())
        );
        assert_eq!(read_rust_toolchain_legacy(b""), None);
        // A TOML document without a channel is not a bare channel line.
        assert_eq!(
            read_rust_toolchain_legacy(b"[toolchain]\ncomponents = [\"rustfmt\"]\n"),
            None
        );
    }

    #[test]
    fn go_mod_readers_separate_minimum_from_exact() {
        let bytes = b"module example.com/m\n\ngo 1.22.0 // minimum\ntoolchain go1.24.2\n";
        assert_eq!(read_go_mod(bytes), Some("1.22.0".into()));
        assert_eq!(read_go_mod_toolchain(bytes), Some("1.24.2".into()));
        assert_eq!(read_go_mod(b"module m\n"), None);
        assert_eq!(read_go_mod_toolchain(b"module m\ngo 1.22\n"), None);
        assert_eq!(read_go_mod_toolchain(b"go 1.22\ntoolchain default\n"), None);
        // A bare directive earlier in the file does not hide a later one.
        assert_eq!(read_go_mod(b"go\ngo 1.22\n"), Some("1.22".into()));
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
            "std::env",
        ] {
            assert!(
                !non_test.contains(marker),
                "reader mentions process API {marker:?}"
            );
        }
        // Every ecosystem's rows parse under that guard, so a reader that
        // delegates to a tool would have nowhere to hide its output.
        let (_temp, root) = project();
        for ecosystem in ["python", "node", "ruby", "go", "rust", "elixir", "dotnet"] {
            let rows = discover(&root, ecosystem).unwrap();
            assert!(!rows.is_empty(), "{ecosystem} consults no source");
        }
    }

    #[test]
    fn discovery_records_absence_instead_of_omitting() {
        let (temp, root) = project();
        let dir = temp.0.join("proj");
        let rows = discover(&root, "node").unwrap();
        assert_eq!(rows.len(), 2);
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
        std::fs::write(
            dir.join("package.json"),
            "{\"engines\": {\"node\": \"24.20.0\"}}\n",
        )
        .unwrap();
        let rows = discover(&root, "node").unwrap();
        assert_eq!(rows[1].value.as_deref(), Some("24.20.0"));
        assert!(!rows[1].absent);
    }

    #[test]
    fn discovery_follows_the_precedence_table() {
        let (_temp, root) = project();
        let consulted = |ecosystem: &str| -> Vec<(String, String)> {
            discover(&root, ecosystem)
                .unwrap()
                .into_iter()
                .map(|row| (row.path.display().to_string(), row.field))
                .collect()
        };
        let pairs = |list: &[(&str, &str)]| -> Vec<(String, String)> {
            list.iter()
                .map(|(path, field)| (path.to_string(), field.to_string()))
                .collect()
        };
        assert_eq!(
            consulted("python"),
            pairs(&[
                (".python-version", "version"),
                ("pyproject.toml", "project.requires-python"),
                ("pyproject.toml", "tool.poetry.dependencies.python"),
            ])
        );
        assert_eq!(
            consulted("node"),
            pairs(&[
                (".node-version", "version"),
                ("package.json", "engines.node")
            ])
        );
        assert_eq!(
            consulted("rust"),
            pairs(&[
                ("rust-toolchain", "toolchain.channel"),
                ("rust-toolchain.toml", "toolchain.channel"),
            ])
        );
        assert_eq!(
            consulted("go"),
            pairs(&[("go.mod", "go"), ("go.mod", "toolchain")])
        );
        assert_eq!(
            consulted("ruby"),
            pairs(&[(".ruby-version", "version"), (".tool-versions", "ruby")])
        );
        assert_eq!(
            consulted("elixir"),
            pairs(&[(".tool-versions", "erlang"), (".tool-versions", "elixir")])
        );
        assert_eq!(
            consulted("dotnet"),
            pairs(&[
                ("global.json", "sdk.version"),
                ("global.json", "sdk.rollForward"),
            ])
        );
    }

    #[test]
    fn discovery_refuses_a_symlinked_input() {
        let (temp, root) = project();
        let victim = temp.0.join("victim");
        std::fs::write(&victim, b"3.12.1\n").unwrap();
        std::os::unix::fs::symlink(&victim, temp.0.join("proj/.python-version")).unwrap();
        let error = discover(&root, "python").unwrap_err();
        assert!(error.to_string().contains("is a symlink"), "{error}");
    }

    #[test]
    fn computed_only_message_names_a_file() {
        assert!(computed_only_message("python").contains(".python-version"));
        assert!(computed_only_message("node").contains(".node-version"));
        assert!(computed_only_message("dotnet").contains("global.json"));
    }
}

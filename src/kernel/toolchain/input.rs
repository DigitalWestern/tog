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

/// The `[toolchain]` table of a rustup toolchain file, as a TOML table.
pub type ToolchainTable = toml::map::Map<String, toml::Value>;

/// The file name a toolchain-file error names.
fn toolchain_file_name(legacy: bool) -> &'static str {
    if legacy {
        "rust-toolchain"
    } else {
        "rust-toolchain.toml"
    }
}

/// The `[toolchain]` table of a rustup toolchain file, or `None` for a
/// legacy `rust-toolchain` that is a bare channel line. A file that cannot
/// be read as the format its name promises is refused here, in the
/// parser's words, rather than recorded as a file without the field: a lock
/// must never read a malformed toolchain file as one that asks for nothing.
///
/// `rust-toolchain.toml` must be UTF-8 TOML with a `[toolchain]` table, as
/// rustup requires. The legacy `rust-toolchain` is that TOML document when
/// it parses as one with a `toolchain` key, and a bare channel line
/// otherwise.
pub fn rust_toolchain_table(bytes: &[u8], legacy: bool) -> io::Result<Option<ToolchainTable>> {
    let name = toolchain_file_name(legacy);
    let bad = |what: String| io::Error::new(io::ErrorKind::InvalidData, format!("{name}: {what}"));
    let text = std::str::from_utf8(bytes).map_err(|_| bad("is not UTF-8".into()))?;
    let document = match toml::from_str::<toml::Value>(text) {
        Ok(document) => document,
        Err(_) if legacy => return Ok(None),
        Err(error) => return Err(bad(error.to_string().trim().to_string())),
    };
    match document.get("toolchain") {
        Some(toml::Value::Table(table)) => Ok(Some(table.clone())),
        Some(_) => Err(bad("[toolchain] must be a table".into())),
        None if legacy => Ok(None),
        None => Err(bad("has no [toolchain] table".into())),
    }
}

/// `[toolchain] channel`, which must be a string when it is present.
pub fn toolchain_channel(table: &ToolchainTable, legacy: bool) -> io::Result<Option<String>> {
    match table.get("channel") {
        None => Ok(None),
        Some(toml::Value::String(text)) => Ok(Some(text.clone())),
        Some(_) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{}: toolchain.channel must be a string",
                toolchain_file_name(legacy)
            ),
        )),
    }
}

/// `rust-toolchain.toml`: `[toolchain] channel = "1.96.1"`.
pub fn read_rust_toolchain(bytes: &[u8]) -> io::Result<Option<String>> {
    match rust_toolchain_table(bytes, false)? {
        Some(table) => toolchain_channel(&table, false),
        None => Ok(None),
    }
}

/// Legacy `rust-toolchain`: a bare channel on the first line, or the same
/// TOML document rustup accepts at that name. A document with a
/// `[toolchain]` table is read as TOML only, so a table without a channel
/// yields no value instead of the literal header line.
pub fn read_rust_toolchain_legacy(bytes: &[u8]) -> io::Result<Option<String>> {
    match rust_toolchain_table(bytes, true)? {
        Some(table) => toolchain_channel(&table, true),
        None => Ok(first_line(bytes)),
    }
}

/// The list fields of a `[toolchain]` table the lock records, each with the
/// input field it is recorded under.
pub const RUST_TOOLCHAIN_LISTS: [(&str, &str); 2] = [
    ("components", "toolchain.components"),
    ("targets", "toolchain.targets"),
];

/// `[toolchain] profile`, and the input field it is recorded under.
pub const RUST_TOOLCHAIN_PROFILE: (&str, &str) = ("profile", "toolchain.profile");

/// The profiles rustup defines. Anything else is refused, as rustup refuses
/// it, rather than recorded.
pub const RUST_PROFILES: [&str; 3] = ["minimal", "default", "complete"];

/// Every `[toolchain]` field besides the channel that the lock records.
pub const RUST_TOOLCHAIN_REQUESTS: [(&str, &str); 3] = [
    RUST_TOOLCHAIN_LISTS[0],
    RUST_TOOLCHAIN_LISTS[1],
    RUST_TOOLCHAIN_PROFILE,
];

/// `[toolchain] path`, and the input field it is recorded under: a toolchain
/// that is a directory on this machine, as rustup reads it, instead of a
/// channel tog provisions.
pub const RUST_TOOLCHAIN_PATH: (&str, &str) = ("path", "toolchain.path");

/// `[toolchain] path` as written, when present. rustup refuses a path next
/// to a channel, and next to components, targets or a profile (a local tree
/// is used as it is, nothing is installed into it); so does this reader,
/// rather than record a request that means nothing.
pub fn toolchain_path(table: &ToolchainTable, legacy: bool) -> io::Result<Option<String>> {
    let name = toolchain_file_name(legacy);
    let bad = |what: String| io::Error::new(io::ErrorKind::InvalidData, format!("{name}: {what}"));
    let path = match table.get(RUST_TOOLCHAIN_PATH.0) {
        None => return Ok(None),
        Some(toml::Value::String(path)) if !path.is_empty() => path.clone(),
        Some(_) => return Err(bad("toolchain.path must be a non-empty string".into())),
    };
    if table.contains_key("channel") {
        return Err(bad(format!(
            "toolchain.path ({path}) and toolchain.channel name two toolchains; keep one (rustup refuses both)"
        )));
    }
    for (key, _) in RUST_TOOLCHAIN_REQUESTS {
        if table.contains_key(key) {
            return Err(bad(format!(
                "toolchain.path ({path}) is used as it is, so toolchain.{key} cannot be installed into it; \
                 remove toolchain.{key} or name a channel instead (rustup refuses both)"
            )));
        }
    }
    Ok(Some(path))
}

/// `[toolchain] profile`: one of [`RUST_PROFILES`] when present.
pub fn toolchain_profile(table: &ToolchainTable, legacy: bool) -> io::Result<Option<String>> {
    match table.get(RUST_TOOLCHAIN_PROFILE.0) {
        None => Ok(None),
        Some(toml::Value::String(name)) if RUST_PROFILES.contains(&name.as_str()) => {
            Ok(Some(name.clone()))
        }
        Some(other) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{}: toolchain.profile must be one of {}, not {other}",
                toolchain_file_name(legacy),
                RUST_PROFILES.join(", ")
            ),
        )),
    }
}

/// The separator inside a recorded list value. No name can contain it:
/// [`toolchain_list`] refuses every name outside `[A-Za-z0-9._-]`.
pub const LIST_SEPARATOR: char = ',';

/// `[toolchain] components` or `targets` as the one canonical value the lock
/// records: the names sorted, deduplicated and joined with
/// [`LIST_SEPARATOR`], so two files asking for the same set give the same
/// bytes. An absent or empty list asks for nothing and has no value. A value
/// that is not an array of plain names is refused.
pub fn toolchain_list(
    table: &ToolchainTable,
    key: &str,
    legacy: bool,
) -> io::Result<Option<String>> {
    let bad = |what: String| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{}: toolchain.{key} {what}", toolchain_file_name(legacy)),
        )
    };
    let Some(value) = table.get(key) else {
        return Ok(None);
    };
    let toml::Value::Array(items) = value else {
        return Err(bad("must be an array of strings".into()));
    };
    let mut names = std::collections::BTreeSet::new();
    for item in items {
        let toml::Value::String(name) = item else {
            return Err(bad("must be an array of strings".into()));
        };
        let plain = !name.is_empty()
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
        if !plain {
            return Err(bad(format!(
                "names {name:?}, which is not a component or target name"
            )));
        }
        names.insert(name.as_str());
    }
    if names.is_empty() {
        return Ok(None);
    }
    Ok(Some(
        names
            .into_iter()
            .collect::<Vec<_>>()
            .join(&LIST_SEPARATOR.to_string()),
    ))
}

/// A recorded list value back to its names, in recorded (sorted) order.
pub fn split_list(value: &str) -> Vec<String> {
    value
        .split(LIST_SEPARATOR)
        .filter(|name| !name.is_empty())
        .map(str::to_string)
        .collect()
}

/// The Rust rows: each toolchain file's channel, then the lists, the
/// profile and the local toolchain path it asks for. A channel row is always
/// written, as every other ecosystem's rows are. A list, profile or path row
/// is written only when the file names one, so a lock minted before they
/// were recorded stays byte-identical for a project that asks for none, and
/// one appearing or disappearing is a row only one side has, which
/// staleness calls stale.
fn rust_rows(root: &ProjectRoot) -> io::Result<Vec<InputRow>> {
    let mut rows = Vec::new();
    for (path, legacy) in [("rust-toolchain", true), ("rust-toolchain.toml", false)] {
        let field = "toolchain.channel";
        let Some(bytes) = root.read_file(Path::new(path))? else {
            rows.push(InputRow::missing(path, field));
            continue;
        };
        let table = rust_toolchain_table(&bytes, legacy)?;
        let channel = match &table {
            Some(table) => toolchain_channel(table, legacy)?,
            None => first_line(&bytes),
        };
        rows.push(match channel {
            Some(value) => InputRow::present(path, field, value, &bytes),
            None => InputRow::present_without_value(path, field, &bytes),
        });
        let Some(table) = table else {
            continue;
        };
        for (key, field) in RUST_TOOLCHAIN_LISTS {
            if let Some(value) = toolchain_list(&table, key, legacy)? {
                rows.push(InputRow::present(path, field, value, &bytes));
            }
        }
        if let Some(value) = toolchain_profile(&table, legacy)? {
            rows.push(InputRow::present(
                path,
                RUST_TOOLCHAIN_PROFILE.1,
                value,
                &bytes,
            ));
        }
        if let Some(value) = toolchain_path(&table, legacy)? {
            rows.push(InputRow::present(
                path,
                RUST_TOOLCHAIN_PATH.1,
                value,
                &bytes,
            ));
        }
    }
    Ok(rows)
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
        "rust" => rust_rows(root)?,
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
        let modern = |bytes: &[u8]| read_rust_toolchain(bytes).unwrap();
        let legacy = |bytes: &[u8]| read_rust_toolchain_legacy(bytes).unwrap();
        let bytes = b"[toolchain]\nchannel = \"1.96.1\"\n";
        assert_eq!(modern(bytes), Some("1.96.1".into()));
        assert_eq!(modern(b"[toolchain]\n"), None);
        assert_eq!(legacy(bytes), Some("1.96.1".into()));
        assert_eq!(legacy(b"1.96.1\n"), Some("1.96.1".into()));
        assert_eq!(legacy(b""), None);
        // A TOML document without a channel is not a bare channel line.
        assert_eq!(legacy(b"[toolchain]\ncomponents = [\"rustfmt\"]\n"), None);
    }

    /// A toolchain file that is not the format its name promises is refused
    /// in the parser's words, never read as a file that asks for nothing.
    #[test]
    fn a_malformed_rust_toolchain_file_is_refused_not_absent() {
        for (bytes, words) in [
            (&b"not toml ["[..], "rust-toolchain.toml:"),
            (b"[project]\nname = \"x\"\n", "has no [toolchain] table"),
            (b"toolchain = \"1.96.1\"\n", "[toolchain] must be a table"),
            (
                b"[toolchain]\nchannel = 1\n",
                "toolchain.channel must be a string",
            ),
            (b"\xff\xfe", "is not UTF-8"),
        ] {
            let error = read_rust_toolchain(bytes).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            assert!(error.to_string().contains(words), "{error}");
        }
        // The legacy name is a bare channel line unless it is TOML with a
        // `toolchain` key; that document is held to the same rules.
        assert_eq!(
            read_rust_toolchain_legacy(b"not toml [\n").unwrap(),
            Some("not toml [".into())
        );
        let error = read_rust_toolchain_legacy(b"[toolchain]\nchannel = []\n").unwrap_err();
        assert!(error.to_string().starts_with("rust-toolchain:"), "{error}");
        assert!(read_rust_toolchain_legacy(b"\xff").is_err());
    }

    fn list(bytes: &[u8], key: &str) -> io::Result<Option<String>> {
        let table = rust_toolchain_table(bytes, false).unwrap().unwrap();
        toolchain_list(&table, key, false)
    }

    #[test]
    fn toolchain_lists_are_sorted_deduplicated_and_empty_is_absent() {
        let bytes = b"[toolchain]\ncomponents = [\"rustfmt\", \"clippy\", \"rustfmt\"]\n\
                      targets = [\"wasm32-unknown-unknown\"]\n";
        assert_eq!(
            list(bytes, "components").unwrap(),
            Some("clippy,rustfmt".into())
        );
        assert_eq!(
            list(bytes, "targets").unwrap(),
            Some("wasm32-unknown-unknown".into())
        );
        assert_eq!(
            list(b"[toolchain]\ncomponents = []\n", "components").unwrap(),
            None
        );
        assert_eq!(list(b"[toolchain]\n", "targets").unwrap(), None);
        assert_eq!(
            split_list("clippy,rustfmt"),
            vec!["clippy".to_string(), "rustfmt".to_string()]
        );
        for bad in [
            &b"[toolchain]\ncomponents = \"clippy\"\n"[..],
            b"[toolchain]\ncomponents = [1]\n",
            b"[toolchain]\ncomponents = [\"a,b\"]\n",
            b"[toolchain]\ncomponents = [\"\"]\n",
            b"[toolchain]\ncomponents = [\"has space\"]\n",
        ] {
            let error = list(bad, "components").unwrap_err();
            assert!(
                error.to_string().contains("toolchain.components"),
                "{error}"
            );
        }
    }

    #[test]
    fn rust_discovery_records_lists_only_when_asked_for() {
        let (temp, root) = project();
        let dir = temp.0.join("proj");
        let fields = |root: &ProjectRoot| -> Vec<(String, String, Option<String>)> {
            discover(root, "rust")
                .unwrap()
                .into_iter()
                .map(|row| (row.path.display().to_string(), row.field, row.value))
                .collect()
        };
        std::fs::write(
            dir.join("rust-toolchain.toml"),
            "[toolchain]\nchannel = \"1.96.1\"\n",
        )
        .unwrap();
        // A file with no lists gives exactly the rows it always gave.
        assert_eq!(
            fields(&root),
            vec![
                ("rust-toolchain".into(), "toolchain.channel".into(), None),
                (
                    "rust-toolchain.toml".into(),
                    "toolchain.channel".into(),
                    Some("1.96.1".into())
                ),
            ]
        );
        std::fs::write(
            dir.join("rust-toolchain.toml"),
            "[toolchain]\nchannel = \"1.96.1\"\ntargets = [\"wasm32-unknown-unknown\"]\n\
             components = [\"rustfmt\", \"clippy\"]\n",
        )
        .unwrap();
        let rows = discover(&root, "rust").unwrap();
        assert_eq!(rows.len(), 4);
        assert_eq!(rows[2].field, "toolchain.components");
        assert_eq!(rows[2].value.as_deref(), Some("clippy,rustfmt"));
        assert_eq!(rows[3].field, "toolchain.targets");
        assert_eq!(rows[3].value.as_deref(), Some("wasm32-unknown-unknown"));
        assert!(rows[2..].iter().all(|row| row.sha256 == rows[1].sha256));
        // A profile is one more row, after the lists.
        std::fs::write(
            dir.join("rust-toolchain.toml"),
            "[toolchain]\nchannel = \"1.96.1\"\nprofile = \"complete\"\n",
        )
        .unwrap();
        let rows = discover(&root, "rust").unwrap();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[2].field, "toolchain.profile");
        assert_eq!(rows[2].value.as_deref(), Some("complete"));
        for bad in ["profile = \"full\"", "profile = 1"] {
            std::fs::write(
                dir.join("rust-toolchain.toml"),
                format!("[toolchain]\nchannel = \"1.96.1\"\n{bad}\n"),
            )
            .unwrap();
            let error = discover(&root, "rust").unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("toolchain.profile must be one of"),
                "{error}"
            );
        }
        // A local toolchain is one row naming the tree as written, beside a
        // channel row with no value.
        std::fs::write(
            dir.join("rust-toolchain.toml"),
            "[toolchain]\npath = \"/custom/rust\"\n",
        )
        .unwrap();
        assert_eq!(
            fields(&root),
            vec![
                ("rust-toolchain".into(), "toolchain.channel".into(), None),
                (
                    "rust-toolchain.toml".into(),
                    "toolchain.channel".into(),
                    None
                ),
                (
                    "rust-toolchain.toml".into(),
                    "toolchain.path".into(),
                    Some("/custom/rust".into())
                ),
            ]
        );
        // What rustup refuses beside a path is refused, not recorded.
        for (extra, words) in [
            ("channel = \"1.96.1\"", "name two toolchains"),
            (
                "components = [\"clippy\"]",
                "toolchain.components cannot be installed",
            ),
            (
                "targets = [\"wasm32-unknown-unknown\"]",
                "toolchain.targets cannot be installed",
            ),
            (
                "profile = \"minimal\"",
                "toolchain.profile cannot be installed",
            ),
        ] {
            std::fs::write(
                dir.join("rust-toolchain.toml"),
                format!("[toolchain]\npath = \"/custom/rust\"\n{extra}\n"),
            )
            .unwrap();
            let error = discover(&root, "rust").unwrap_err();
            assert!(error.to_string().contains(words), "{extra}: {error}");
        }
        for bad in ["path = \"\"", "path = 1"] {
            std::fs::write(
                dir.join("rust-toolchain.toml"),
                format!("[toolchain]\n{bad}\n"),
            )
            .unwrap();
            let error = discover(&root, "rust").unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("toolchain.path must be a non-empty string"),
                "{error}"
            );
        }
        // A malformed file stops discovery; it is never recorded as absent.
        std::fs::write(dir.join("rust-toolchain.toml"), "[toolchain\n").unwrap();
        let error = discover(&root, "rust").unwrap_err();
        assert!(error.to_string().contains("rust-toolchain.toml"), "{error}");
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
        assert!(rows[1].sha256.is_some());
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
}

//! The layering rules of REFACTOR.md §2, enforced by a source scan so the
//! refactor stays done: `commands → tailors → comforter → kernel`, one
//! direction only, and no tailor names another tailor.
//!
//! Test code (everything from `#[cfg(test)] mod tests` on) is exempt: tests
//! may wire the whole crate together. Size budgets (§2 principle 5) are
//! reported, not enforced, so drift is visible in `cargo test` output.

use std::fs;
use std::path::{Path, PathBuf};

fn src() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
    out.sort();
}

/// The non-test part of a file: everything before its `mod tests`.
fn non_test(text: &str) -> &str {
    match text.find("#[cfg(test)]\nmod tests") {
        Some(index) => &text[..index],
        None => text,
    }
}

/// Every `crate::a::b` path in `text`, with grouped `use crate::{a, b::c}`
/// imports expanded one level, as segment vectors.
fn crate_paths(text: &str) -> Vec<Vec<String>> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(index) = rest.find("crate::") {
        let after = &rest[index + "crate::".len()..];
        let head: String = after
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == ':')
            .collect();
        let head_segments: Vec<String> = head
            .split("::")
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect();
        let tail = &after[head.len()..];
        if let Some(group) = tail.strip_prefix('{') {
            let close = group.find('}').unwrap_or(group.len());
            for item in group[..close].split(',') {
                let item = item.trim();
                if item.is_empty() {
                    continue;
                }
                let mut segments = head_segments.clone();
                segments.extend(
                    item.split("::")
                        .map(|s| s.trim().split_whitespace().next().unwrap_or("").to_string())
                        .filter(|s| !s.is_empty() && !s.starts_with('{')),
                );
                out.push(segments);
            }
        } else {
            out.push(head_segments);
        }
        rest = &rest[index + "crate::".len()..];
    }
    out
}

/// Layer of a source file: the first folder under `src/`, or the file stem.
fn layer(relative: &Path) -> String {
    let mut components = relative.components();
    let first = components.next().unwrap().as_os_str().to_string_lossy();
    if first.ends_with(".rs") {
        first.trim_end_matches(".rs").to_string()
    } else {
        first.to_string()
    }
}

/// The one-way exceptions, each documented where it lives. Adding to this
/// list is a shared-layer review (REFACTOR.md §2 principle 2).
const ALLOWED: &[(&str, &str, &str)] = &[
    // Python sdists with Rust extensions build with the cargo tailor's
    // pinned toolchain. A kernel-level toolchain provider would remove this
    // (FOLLOW-UPS.md).
    (
        "tailors/python/build.rs",
        "tailors::cargo",
        "Rust extension builds",
    ),
    // npm install scripts (node-gyp) run under a pinned CPython and the
    // Python tailor's artifact and native-lib provisioning. Those two
    // modules are ecosystem-neutral in practice and belong in a shared
    // toolchain provider (FOLLOW-UPS.md).
    (
        "tailors/node/realize.rs",
        "tailors::python",
        "node-gyp install scripts",
    ),
    (
        "tailors/node/project.rs",
        "tailors::python",
        "native-lib env references",
    ),
    // The dependency-spec validator lives with the command that owns the
    // spec grammar; cli calls it for argv validation only.
    (
        "cli/parse.rs",
        "commands::deps::validate_spec",
        "argv validation",
    ),
];

fn allowed(relative: &str, path: &[String]) -> bool {
    let joined = path.join("::");
    ALLOWED
        .iter()
        .any(|(file, prefix, _)| relative == *file && joined.starts_with(prefix))
}

#[test]
fn layers_point_one_way() {
    let root = src();
    let mut files = Vec::new();
    rust_files(&root, &mut files);
    let mut violations = Vec::new();
    for file in &files {
        let relative = file.strip_prefix(&root).unwrap();
        let relative_str = relative.to_string_lossy().replace('\\', "/");
        let text = fs::read_to_string(file).unwrap();
        let layer = layer(relative);
        for path in crate_paths(non_test(&text)) {
            let Some(target) = path.first() else { continue };
            let forbidden = match layer.as_str() {
                "kernel" => matches!(
                    target.as_str(),
                    "tailors" | "comforter" | "commands" | "cli"
                ),
                "comforter" => matches!(target.as_str(), "commands" | "cli"),
                "tailors" => {
                    matches!(target.as_str(), "commands" | "cli")
                        || (target == "tailors"
                            && path.len() >= 2
                            && relative.components().nth(1).is_some_and(|own| {
                                let own = own.as_os_str().to_string_lossy();
                                // another tailor's folder: tailors::<other>::…
                                path[1] != own
                                    && files.iter().any(|f| {
                                        f.strip_prefix(&root)
                                            .unwrap()
                                            .starts_with(Path::new("tailors").join(&path[1]))
                                    })
                            }))
                }
                "cli" => matches!(
                    target.as_str(),
                    "tailors" | "comforter" | "kernel" | "commands"
                ),
                _ => false,
            };
            if forbidden && !allowed(&relative_str, &path) {
                violations.push(format!("{relative_str}: crate::{}", path.join("::")));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "layering violations (REFACTOR.md §2 principle 1):\n  {}",
        violations.join("\n  ")
    );
}

/// Size budgets are advisory: this test prints the files and functions
/// over budget so `cargo test -- --nocapture architecture` shows the drift.
#[test]
fn size_budgets_are_reported() {
    let root = src();
    let mut files = Vec::new();
    rust_files(&root, &mut files);
    let mut over_files = Vec::new();
    let mut over_functions = Vec::new();
    for file in &files {
        let relative = file
            .strip_prefix(&root)
            .unwrap()
            .to_string_lossy()
            .to_string();
        let text = fs::read_to_string(file).unwrap();
        let body = non_test(&text);
        let lines = body.lines().count();
        if lines > 1500 {
            over_files.push(format!("{lines:6}  {relative}"));
        }
        for (name, length) in function_lengths(body) {
            if length > 150 {
                over_functions.push(format!("{length:6}  {relative}::{name}"));
            }
        }
    }
    over_files.sort_by(|a, b| b.cmp(a));
    over_functions.sort_by(|a, b| b.cmp(a));
    println!("files over 1,500 non-test lines: {}", over_files.len());
    for line in &over_files {
        println!("{line}");
    }
    println!(
        "non-test functions over 150 lines: {}",
        over_functions.len()
    );
    for line in &over_functions {
        println!("{line}");
    }
}

/// Rough function lengths: a `fn` at indentation ≤ 4 runs to its matching
/// brace, with strings, chars, and comments blanked so their braces do not
/// count.
fn function_lengths(text: &str) -> Vec<(String, usize)> {
    let clean = blank_literals(text);
    let lines: Vec<&str> = clean.lines().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        let trimmed = line.trim_start();
        let indent = line.len() - trimmed.len();
        let name = if indent <= 4 { fn_name(trimmed) } else { None };
        let Some(name) = name else {
            i += 1;
            continue;
        };
        let mut depth = 0i32;
        let mut started = false;
        let mut j = i;
        while j < lines.len() {
            for c in lines[j].chars() {
                if c == '{' {
                    depth += 1;
                    started = true;
                } else if c == '}' {
                    depth -= 1;
                }
            }
            if started && depth <= 0 {
                break;
            }
            if !started && lines[j].trim_end().ends_with(';') {
                break;
            }
            j += 1;
        }
        out.push((name, j - i + 1));
        i = j + 1;
    }
    out
}

fn fn_name(line: &str) -> Option<String> {
    let rest = line
        .strip_prefix("pub(crate) ")
        .or_else(|| line.strip_prefix("pub(super) "))
        .or_else(|| line.strip_prefix("pub "))
        .unwrap_or(line);
    let rest = rest.strip_prefix("unsafe ").unwrap_or(rest);
    let rest = rest.strip_prefix("fn ")?;
    let name: String = rest
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect();
    (!name.is_empty()).then_some(name)
}

fn blank_literals(text: &str) -> String {
    let bytes: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    let n = bytes.len();
    while i < n {
        let c = bytes[i];
        if c == '/' && i + 1 < n && bytes[i + 1] == '/' {
            while i < n && bytes[i] != '\n' {
                i += 1;
            }
            continue;
        }
        if c == '/' && i + 1 < n && bytes[i + 1] == '*' {
            i += 2;
            while i + 1 < n && !(bytes[i] == '*' && bytes[i + 1] == '/') {
                if bytes[i] == '\n' {
                    out.push('\n');
                }
                i += 1;
            }
            i += 2;
            continue;
        }
        if c == 'r' && i + 1 < n && (bytes[i + 1] == '"' || bytes[i + 1] == '#') {
            let mut j = i + 1;
            let mut hashes = 0;
            while j < n && bytes[j] == '#' {
                hashes += 1;
                j += 1;
            }
            if j < n && bytes[j] == '"' {
                j += 1;
                loop {
                    if j >= n {
                        break;
                    }
                    if bytes[j] == '"' && (j + 1..=j + hashes).all(|k| k < n && bytes[k] == '#') {
                        j += 1 + hashes;
                        break;
                    }
                    if bytes[j] == '\n' {
                        out.push('\n');
                    }
                    j += 1;
                }
                i = j;
                continue;
            }
        }
        if c == '"' {
            let mut j = i + 1;
            while j < n && bytes[j] != '"' {
                if bytes[j] == '\\' {
                    j += 1;
                }
                if j < n && bytes[j] == '\n' {
                    out.push('\n');
                }
                j += 1;
            }
            i = j + 1;
            continue;
        }
        if c == '\'' {
            if i + 2 < n && bytes[i + 1] != '\\' && bytes[i + 2] == '\'' {
                i += 3;
                continue;
            }
            if i + 1 < n && bytes[i + 1] == '\\' {
                let mut j = i + 2;
                while j < n && bytes[j] != '\'' {
                    j += 1;
                }
                i = j + 1;
                continue;
            }
        }
        out.push(c);
        i += 1;
    }
    out
}

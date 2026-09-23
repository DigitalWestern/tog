//! The layering rules of docs/human/ARCHITECTURE.md ("Layering rules"),
//! enforced by a source scan: `commands → tailors → comforter → kernel`, one
//! direction only, and no tailor names another tailor.
//!
//! Test code (everything from `#[cfg(test)] mod tests` on) is exempt: tests
//! may wire the whole crate together. Size budgets (layering rule 5) are
//! reported, not enforced, so drift is visible in `cargo test` output.
//!
//! Four housekeeping rules are enforced the same way: a test that sets
//! `TOG_STORE` holds `STORE_ENV_LOCK`, comments describe code rather
//! than cite plan documents or review rounds, narration goes through
//! `kernel::ui` rather than a raw `eprintln!`, and `docs/agent/` holds only
//! its two files.

use std::fs;
use std::path::{Path, PathBuf};

fn src() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Every `.rs` file under `src/` and `tests/`, as (repo-relative path, text).
fn all_sources() -> Vec<(String, String)> {
    let root = repo();
    let mut files = Vec::new();
    rust_files(&root.join("src"), &mut files);
    rust_files(&root.join("tests"), &mut files);
    files
        .into_iter()
        .map(|file| {
            let relative = file
                .strip_prefix(&root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            let text = fs::read_to_string(&file).unwrap();
            (relative, text)
        })
        .collect()
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
/// list is a shared-layer review (layering rule 2).
const ALLOWED: &[(&str, &str, &str)] = &[
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
        "layering violations (docs/human/ARCHITECTURE.md, layering rule 1):\n  {}",
        violations.join("\n  ")
    );
}

/// Size budgets are advisory: this test prints the files and functions
/// over budget so `cargo test --test architecture -- --nocapture` shows the
/// drift.
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

/// `TOG_STORE` is process-global. A test that sets or clears it without
/// holding `store::STORE_ENV_LOCK` redirects a concurrent test to the real
/// store, so any file that touches the variable must name the lock.
#[test]
fn store_env_writes_hold_the_lock() {
    let mut violations = Vec::new();
    for (relative, text) in all_sources() {
        let writes =
            text.contains("set_var(\"TOG_STORE\"") || text.contains("remove_var(\"TOG_STORE\"");
        if writes && !text.contains("STORE_ENV_LOCK") {
            violations.push(relative);
        }
    }
    assert!(
        violations.is_empty(),
        "files that write TOG_STORE without STORE_ENV_LOCK:\n  {}",
        violations.join("\n  ")
    );
}

/// Plan documents and review rounds get deleted; a comment that cites one
/// goes stale with it. Comments describe the code they sit on instead.
#[test]
fn comments_do_not_cite_plans() {
    const CITATIONS: &[&str] = &[
        "DESIGNS.md",
        "FOLLOW-UPS.md",
        "NEXT.md",
        "REFACTOR.md",
        "REVIEW.md",
        "Sol review",
        "per Sol",
    ];
    // A word followed directly by a digit: a plan item number or review round.
    const NUMBERED: &[&str] = &["item ", "WP", "A-R", "Sol r"];
    let mut violations = Vec::new();
    for (relative, text) in all_sources() {
        for (index, line) in text.lines().enumerate() {
            let Some(comment) = comment_text(line) else {
                continue;
            };
            let cited = CITATIONS.iter().any(|c| comment.contains(c))
                || NUMBERED.iter().any(|word| {
                    comment.match_indices(word).any(|(at, _)| {
                        let before_ok = at == 0
                            || !comment[..at]
                                .chars()
                                .next_back()
                                .is_some_and(|c| c.is_alphanumeric());
                        let after = comment[at + word.len()..].chars().next();
                        before_ok && after.is_some_and(|c| c.is_ascii_digit())
                    })
                });
            if cited {
                violations.push(format!("{relative}:{}: {}", index + 1, comment.trim()));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "comments citing plan documents or review rounds:\n  {}",
        violations.join("\n  ")
    );
}

/// The comment on a line: everything from a `//` that sits outside a string
/// or char literal. Good enough for a lint; a line the scanner misreads is a
/// missed comment, not a false report, unless a literal on the same line
/// contains one of the cited names.
fn comment_text(line: &str) -> Option<&str> {
    let chars: Vec<(usize, char)> = line.char_indices().collect();
    let mut in_string = false;
    let mut i = 0;
    while i < chars.len() {
        let (at, c) = chars[i];
        if in_string {
            if c == '\\' {
                i += 1;
            } else if c == '"' {
                in_string = false;
            }
        } else if c == '\'' && chars.get(i + 2).is_some_and(|&(_, q)| q == '\'') {
            i += 2;
        } else if c == '"' {
            in_string = true;
        } else if c == '/' && chars.get(i + 1).is_some_and(|&(_, n)| n == '/') {
            return Some(&line[at..]);
        }
        i += 1;
    }
    None
}

/// Narration has one vocabulary: `kernel::ui` prints `tog:` for progress and
/// `tog: warning:` for an advisory, and it is the module `--quiet` and
/// `--no-color` are implemented in. A raw `eprintln!` elsewhere in `src/`
/// bypasses that distinction, so the user cannot tell a fallback from a
/// phase. Test modules are exempt: a skip message is for whoever ran the
/// suite, not for a user.
///
/// Only `eprintln!` is a line of tog's own narration. `eprint!` is the
/// verbatim pass-through of a subprocess's captured output and of an
/// already-rendered usage error, neither of which takes a `tog:` prefix.
#[test]
fn narration_goes_through_kernel_ui() {
    let mut violations = Vec::new();
    for (relative, text) in all_sources() {
        if !relative.starts_with("src/") || relative == "src/kernel/ui.rs" {
            continue;
        }
        for (index, line) in outside_test_modules(&text).lines().enumerate() {
            if line.contains("eprintln!") {
                violations.push(format!("{relative}:{}: {}", index + 1, line.trim()));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "stderr written outside kernel::ui (use ui::note for progress, \
         ui::warning for an advisory, ui::error for a failure):\n  {}",
        violations.join("\n  ")
    );
}

/// The part of a file before its first `#[cfg(test)]` module. Unlike
/// `non_test`, this finds a test module under any name (`mod tests`,
/// `mod patch_snapshot_tests`), which is what a scan for test-only output
/// needs; a `#[cfg(test)]` helper `fn` is not a module and does not cut.
fn outside_test_modules(text: &str) -> &str {
    let mut rest = text;
    let mut consumed = 0;
    while let Some(index) = rest.find("#[cfg(test)]\n") {
        let after = &rest[index + "#[cfg(test)]\n".len()..];
        if after.starts_with("mod ") || after.starts_with("pub mod ") {
            return &text[..consumed + index];
        }
        consumed += index + "#[cfg(test)]\n".len();
        rest = after;
    }
    text
}

/// `docs/agent/` is two files. Ledgers, review reports, and evidence dumps
/// go in pull request descriptions; history is git.
#[test]
fn agent_docs_are_two_files() {
    let mut names: Vec<String> = fs::read_dir(repo().join("docs/agent"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().to_string())
        .collect();
    names.sort();
    assert_eq!(names, ["DESIGNS.md", "HITRATE.md"]);
}

/// A child process that reads or writes a store path runs through
/// `kernel::supervise` with the caller's activity lease, so protection is
/// provable at the call site. The only raw `.status()`, `.output()` or
/// `.spawn()` left in production code are the functions below, each of
/// which touches no store path; the comment above each group says why. A
/// new raw spawn fails here until it either borrows a lease or joins this
/// list with a reason.
const RAW_CHILD_SITES: &[(&str, &str)] = &[
    // `None` arm of `Option<&StoreActivity>`: no store is involved.
    ("src/comforter/mod.rs", "clone_tree_for"),
    ("src/kernel/archive.rs", "list_names"),
    ("src/kernel/archive.rs", "status_for"),
    ("src/tailors/python/build_requires.rs", "output_for"),
    ("src/tailors/python/build_requires.rs", "status_for"),
    // `git ls-remote`: a network query with no working directory.
    ("src/kernel/gitsrc.rs", "run_git"),
    // The `None` arm of the bwrap `--version` and classification probes.
    ("src/kernel/sandbox.rs", "bwrap_preflight_with_activity"),
    // Unmanaged sandbox entry points, for callers that consume no store.
    ("src/kernel/sandbox.rs", "run_bwrap_with_stdout"),
    ("src/kernel/sandbox.rs", "run_seatbelt_status"),
    // Host probes.
    ("src/commands/selfupdate.rs", "smoke_test"),
    ("src/tailors/dotnet/mod.rs", "invoking_uid"),
    ("src/tailors/python/pypi.rs", "detect_host_glibc"),
];

#[test]
fn store_children_borrow_the_callers_lease() {
    let mut found = Vec::new();
    for (relative, text) in all_sources() {
        if !relative.starts_with("src/") || relative == "src/kernel/supervise.rs" {
            continue;
        }
        let clean = blank_literals(outside_test_modules(&text));
        let mut current: Option<String> = None;
        let mut test_only = false;
        let mut previous = "";
        for line in clean.lines() {
            let trimmed = line.trim_start();
            let indent = line.len() - trimmed.len();
            if indent <= 4 {
                if let Some(name) = fn_name(trimmed) {
                    test_only = previous.trim() == "#[cfg(test)]";
                    current = Some(name);
                }
            }
            if !trimmed.is_empty() {
                previous = line;
            }
            if test_only {
                continue;
            }
            if [".status()", ".output()", ".spawn()"]
                .iter()
                .any(|call| line.contains(call))
            {
                let site = (relative.clone(), current.clone().unwrap_or_default());
                if !found.contains(&site) {
                    found.push(site);
                }
            }
        }
    }
    found.sort();
    let mut expected: Vec<(String, String)> = RAW_CHILD_SITES
        .iter()
        .map(|(file, function)| (file.to_string(), function.to_string()))
        .collect();
    expected.sort();
    assert_eq!(
        found, expected,
        "a production child runs without the caller's activity lease; pass \
         `&StoreActivity` to `kernel::supervise` (or, for a child that touches \
         no store path, name it in RAW_CHILD_SITES and DESIGNS.md)"
    );

    // The helpers that run children must not mint a lease of their own: a
    // fresh lease per child is exactly what cannot be proved at the call
    // site.
    for relative in ["src/kernel/supervise.rs", "src/kernel/sandbox.rs"] {
        let text = fs::read_to_string(repo().join(relative)).unwrap();
        assert!(
            !non_test(&text).contains(".activity("),
            "{relative} takes its own activity lease; borrow the caller's"
        );
    }
}

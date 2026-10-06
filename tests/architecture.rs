//! The layering rules of docs/human/ARCHITECTURE.md ("Layering rules"),
//! enforced by a source scan: `commands → tailors → comforter → kernel`, one
//! direction only, and no tailor names another tailor. A command file does
//! not name a tailor's module or spell its name as a string either (the
//! tokens scan below).
//!
//! Test code (everything from `#[cfg(test)] mod tests` on) is exempt: tests
//! may wire the whole crate together. Size budgets (layering rule 5) are a
//! ratchet against `tests/size_baseline.txt`: what is over budget today may
//! shrink, nothing may grow or newly cross a budget.
//!
//! Five housekeeping rules are enforced the same way: a test that sets
//! `TOG_STORE` holds `STORE_ENV_LOCK`, comments describe code rather
//! than cite plan documents or review rounds, narration goes through
//! `kernel::ui` rather than a raw stderr write, HTTP goes through
//! `kernel::fetch` rather than a raw `ureq` call, and `docs/agent/` holds
//! only its two files.

// Tests spawn fixtures and take leases freely (see clippy.toml).
#![allow(clippy::disallowed_methods)]

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

/// Every path `text` names into the crate, as segment vectors from the
/// crate root: `crate::a::b`, `$crate::a::b`, and `super::…` resolved
/// against `module` (the module path of the file, `["kernel", "gc"]` for
/// `src/kernel/gc/mod.rs`). Grouped imports expand at any depth:
/// `use crate::{a::{b, c}, d}` yields `a::b`, `a::c` and `d`, and `self` in
/// a group names the group's own prefix. A `super` inside an inline module
/// resolves one level too high, which can only report a violation that is
/// not there, never hide one.
fn crate_paths(text: &str, module: &[String]) -> Vec<Vec<String>> {
    let chars: Vec<char> = text.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let boundary = i == 0 || !is_ident_char(chars[i - 1]);
        if boundary && starts_with_at(&chars, i, "crate::") {
            let mut at = i + "crate::".len();
            parse_use_tree(&chars, &mut at, Vec::new(), &mut out);
            i = at.max(i + 1);
        } else if boundary && starts_with_at(&chars, i, "super::") {
            let mut prefix = module.to_vec();
            let mut at = i;
            while starts_with_at(&chars, at, "super::") {
                prefix.pop();
                at += "super::".len();
            }
            parse_use_tree(&chars, &mut at, prefix, &mut out);
            i = at.max(i + 1);
        } else {
            i += 1;
        }
    }
    out
}

fn is_ident_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

fn starts_with_at(chars: &[char], at: usize, word: &str) -> bool {
    word.chars()
        .enumerate()
        .all(|(offset, c)| chars.get(at + offset) == Some(&c))
}

fn skip_whitespace(chars: &[char], at: &mut usize) {
    while chars.get(*at).is_some_and(|c| c.is_whitespace()) {
        *at += 1;
    }
}

/// One use tree starting at `at` (`a::b`, `a::{b, c::{d}}`, `a as x`),
/// every leaf path of it pushed to `out` behind `prefix`.
fn parse_use_tree(chars: &[char], at: &mut usize, prefix: Vec<String>, out: &mut Vec<Vec<String>>) {
    let mut segments = prefix;
    loop {
        skip_whitespace(chars, at);
        if chars.get(*at) == Some(&'{') {
            *at += 1;
            loop {
                skip_whitespace(chars, at);
                match chars.get(*at) {
                    None => return,
                    Some('}') => {
                        *at += 1;
                        return;
                    }
                    Some(',') => *at += 1,
                    Some(_) => {
                        let before = *at;
                        parse_use_tree(chars, at, segments.clone(), out);
                        if *at == before {
                            // Not a use tree (`*`, a stray token): step over it.
                            *at += 1;
                        }
                    }
                }
            }
        }
        let start = *at;
        while chars.get(*at).is_some_and(|&c| is_ident_char(c)) {
            *at += 1;
        }
        let word: String = chars[start..*at].iter().collect();
        if word.is_empty() {
            if !segments.is_empty() {
                out.push(segments);
            }
            return;
        }
        if word != "self" {
            segments.push(word);
        }
        let mut next = *at;
        skip_whitespace(chars, &mut next);
        if starts_with_at(chars, next, "::") {
            *at = next + 2;
        } else {
            // `a as x`: the alias is a local name, not a path segment.
            if starts_with_at(chars, next, "as")
                && chars.get(next + 2).is_some_and(|c| c.is_whitespace())
            {
                *at = next + 2;
                skip_whitespace(chars, at);
                while chars.get(*at).is_some_and(|&c| is_ident_char(c)) {
                    *at += 1;
                }
            }
            out.push(segments);
            return;
        }
    }
}

/// The module path of a file under `src/`: `kernel/gc/mod.rs` is
/// `kernel::gc`, `kernel/gc/sweep.rs` is `kernel::gc::sweep`, and the crate
/// roots `lib.rs` and `main.rs` are the empty path.
fn module_path(relative: &Path) -> Vec<String> {
    let mut segments: Vec<String> = relative
        .with_extension("")
        .components()
        .map(|c| c.as_os_str().to_string_lossy().to_string())
        .collect();
    if matches!(
        segments.last().map(String::as_str),
        Some("mod" | "lib" | "main")
    ) {
        segments.pop();
    }
    segments
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
    // Likewise `tog x`'s argument rules, owned by its command.
    (
        "cli/x.rs",
        "commands::x::request_version",
        "argv validation",
    ),
    ("cli/x.rs", "commands::x::split_version", "argv validation"),
    (
        "cli/x.rs",
        "commands::x::validate_from_bin",
        "argv validation",
    ),
    (
        "cli/x.rs",
        "commands::x::validate_package",
        "argv validation",
    ),
];

/// Whether `path`, named in `relative`, is one of the listed exceptions.
/// The match is exact: `tailors::Tailor` allows the trait and nothing that
/// merely starts with its name (`tailors::TailorRegistry`, `tailors::Tailor::x`).
fn allowed(relative: &str, path: &[String]) -> bool {
    let joined = path.join("::");
    ALLOWED
        .iter()
        .any(|(file, exact, _)| relative == *file && joined == *exact)
}

/// The paths `text`, the source of `relative` (under `src/`), names against
/// the layering rules, and how many crate paths it named in all.
/// `tailor_dirs` are the folders under `src/tailors/`, one per tailor.
fn layer_violations(relative: &Path, text: &str, tailor_dirs: &[String]) -> (Vec<String>, usize) {
    let relative_str = relative.to_string_lossy().replace('\\', "/");
    let layer = layer(relative);
    let paths = crate_paths(non_test(text), &module_path(relative));
    let mut violations = Vec::new();
    for path in &paths {
        let Some(target) = path.first() else { continue };
        let forbidden = match layer.as_str() {
            "kernel" => matches!(
                target.as_str(),
                "tailors" | "comforter" | "commands" | "cli"
            ),
            "comforter" => matches!(target.as_str(), "tailors" | "commands" | "cli"),
            "tailors" => {
                matches!(target.as_str(), "commands" | "cli")
                    || (target == "tailors"
                        && path.len() >= 2
                        && relative.components().nth(1).is_some_and(|own| {
                            let own = own.as_os_str().to_string_lossy();
                            // another tailor's folder: tailors::<other>::…
                            path[1] != own && tailor_dirs.contains(&path[1])
                        }))
            }
            // A command reaches a tailor through the trait and the
            // registry, never by its module: tailors::<name>::… (rule 3).
            "commands" => target == "tailors" && path.len() >= 2 && tailor_dirs.contains(&path[1]),
            "cli" => matches!(
                target.as_str(),
                "tailors" | "comforter" | "kernel" | "commands"
            ),
            _ => false,
        };
        if forbidden && !allowed(&relative_str, path) {
            violations.push(format!("{relative_str}: crate::{}", path.join("::")));
        }
    }
    (violations, paths.len())
}

/// The folders under `src/tailors/`: one per tailor.
fn tailor_dirs() -> Vec<String> {
    fs::read_dir(src().join("tailors"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.is_dir())
        .map(|path| path.file_name().unwrap().to_string_lossy().to_string())
        .collect()
}

#[test]
fn layers_point_one_way() {
    let root = src();
    let mut files = Vec::new();
    rust_files(&root, &mut files);
    let dirs = tailor_dirs();
    let mut violations = Vec::new();
    let mut seen = 0;
    for file in &files {
        let relative = file.strip_prefix(&root).unwrap();
        let text = fs::read_to_string(file).unwrap();
        let (found, paths) = layer_violations(relative, &text, &dirs);
        violations.extend(found);
        seen += paths;
    }
    // Positive control: the crate names itself thousands of times. A scan
    // that stops finding paths (a parser regression, a renamed prefix)
    // fails here instead of passing with nothing to check.
    assert!(
        seen >= 1000,
        "the layering scan found only {seen} crate paths under src/; it is passing vacuously"
    );
    assert!(
        violations.is_empty(),
        "layering violations (docs/human/ARCHITECTURE.md, layering rule 1):\n  {}",
        violations.join("\n  ")
    );
}

/// The kernel branches on no ecosystem by name: a `match` arm or a
/// `matches!` alternative that is a tailor's id or lock ecosystem means an
/// eighth ecosystem would have to edit the kernel. What an ecosystem knows
/// goes through a `Tailor` method or a table the tailors install (#255).
#[test]
fn the_kernel_branches_on_no_ecosystem_name() {
    let mut names: Vec<&str> = tog::tailors::registry()
        .iter()
        .flat_map(|tailor| [tailor.id(), tailor.lock_ecosystem()])
        .collect();
    names.sort();
    names.dedup();
    let root = src();
    let mut files = Vec::new();
    rust_files(&root.join("kernel"), &mut files);
    let mut violations = Vec::new();
    for file in &files {
        let text = fs::read_to_string(file).unwrap();
        for (number, line) in non_test(&text).lines().enumerate() {
            if let Some(name) = ecosystem_arm(line, &names) {
                violations.push(format!(
                    "{}:{}: \"{name}\"",
                    file.strip_prefix(&root).unwrap().display(),
                    number + 1
                ));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "the kernel matches on an ecosystem name; give the tailors a method or a table instead:\n  {}",
        violations.join("\n  ")
    );
}

/// The ecosystem `line` branches on: a quoted name followed by `=>` or
/// `|`, or preceded by `|`.
fn ecosystem_arm<'a>(line: &str, names: &[&'a str]) -> Option<&'a str> {
    let code = line.split("//").next().unwrap_or(line);
    names.iter().copied().find(|name| {
        let quoted = format!("\"{name}\"");
        code.match_indices(&quoted).any(|(at, _)| {
            let after = code[at + quoted.len()..].trim_start();
            let before = code[..at].trim_end();
            after.starts_with("=>") || after.starts_with('|') || before.ends_with('|')
        })
    })
}

#[test]
fn the_ecosystem_arm_scan_sees_every_spelling() {
    let names = ["go", "python"];
    for line in [
        "        \"python\" => {",
        "        \"go\" | \"python\" => true,",
        "    matches!(name, \"node\" | \"go\")",
        "        \"python\"=> 1,",
    ] {
        assert!(ecosystem_arm(line, &names).is_some(), "{line}");
    }
    for line in [
        "    let tool = \"go\";",
        "    run(&[\"go\", \"build\"]);",
        "    // \"python\" => no longer here",
        "        \"golang\" => {",
    ] {
        assert_eq!(ecosystem_arm(line, &names), None, "{line}");
    }
}

/// Every spelling of a path into another layer is seen: nested groups,
/// `self` in a group, `super` chains, `$crate`, whitespace inside a group;
/// and paths that stay in the layer are not reported.
#[test]
fn the_layering_scan_sees_every_spelling() {
    let dirs = vec!["node".to_string(), "python".to_string()];
    let kernel = "use crate::{store::Store, kernel::{ui, gc::{sweep::{self, Plan}}}};\n\
        use crate::{\n    comforter::{\n        toolchain as t,\n    },\n};\n\
        use super::super::super::commands::gc;\n\
        use super::sibling;\n\
        fn f() { $crate::cli::parse(); not_crate::tailors::x(); }";
    let (found, _) = layer_violations(Path::new("kernel/gc/sweep.rs"), kernel, &dirs);
    assert_eq!(
        found,
        [
            "kernel/gc/sweep.rs: crate::comforter::toolchain",
            "kernel/gc/sweep.rs: crate::commands::gc",
            "kernel/gc/sweep.rs: crate::cli::parse",
        ]
    );
    assert_eq!(
        crate_paths(kernel, &module_path(Path::new("kernel/gc/sweep.rs")))[..4],
        [
            vec!["store", "Store"],
            vec!["kernel", "ui"],
            vec!["kernel", "gc", "sweep"],
            vec!["kernel", "gc", "sweep", "Plan"],
        ]
    );

    let tailor = "use super::super::node::Lock;\n\
        use super::wheel;\n\
        use crate::tailors::{python::venv, Tailor};";
    let (found, _) = layer_violations(Path::new("tailors/python/sync.rs"), tailor, &dirs);
    assert_eq!(
        found,
        ["tailors/python/sync.rs: crate::tailors::node::Lock"]
    );

    let (found, _) = layer_violations(
        Path::new("kernel/mod.rs"),
        "#[cfg(test)]\nmod tests { use crate::tailors::x; }",
        &dirs,
    );
    assert!(found.is_empty(), "test modules are exempt: {found:?}");
}

/// Size budgets as a ratchet. `tests/size_baseline.txt` lists every file
/// over 1,500 non-test lines and every non-test function over 150 lines,
/// with its size today. Nothing new may cross a budget, nothing listed may
/// grow, and an entry that shrinks or falls back under budget must be
/// written down, so the baseline only ever moves toward empty.
///
/// Baseline format, one entry per line, sorted, `#` comments and blank
/// lines ignored:
///
/// ```text
/// file <non-test lines> <repo-relative path>
/// fn <lines> <repo-relative path>::<name>
/// ```
///
/// A function name that appears more than once in a file (methods of two
/// impls, say) gets `#2`, `#3`, ... after the name for its second and later
/// occurrences, counted in file order. On failure the test prints the whole
/// baseline as it should read now, ready to paste over the file.
#[test]
fn size_budgets_ratchet() {
    const FILE_BUDGET: usize = 1500;
    const FUNCTION_BUDGET: usize = 150;
    let root = repo();
    let mut files = Vec::new();
    rust_files(&src(), &mut files);
    let mut current = std::collections::BTreeMap::new();
    for file in &files {
        let relative = file
            .strip_prefix(&root)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        let text = fs::read_to_string(file).unwrap();
        let body = non_test(&text);
        let lines = body.lines().count();
        if lines > FILE_BUDGET {
            current.insert(format!("file {relative}"), lines);
        }
        let mut seen = std::collections::BTreeMap::<String, usize>::new();
        for (name, length) in function_lengths(body) {
            let count = seen.entry(name.clone()).or_default();
            *count += 1;
            let name = if *count == 1 {
                name
            } else {
                format!("{name}#{count}")
            };
            if length > FUNCTION_BUDGET {
                current.insert(format!("fn {relative}::{name}"), length);
            }
        }
    }

    let baseline_path = root.join("tests/size_baseline.txt");
    let baseline_text = fs::read_to_string(&baseline_path).unwrap_or_default();
    let mut baseline = std::collections::BTreeMap::new();
    for line in baseline_text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.splitn(3, ' ');
        let (Some(kind), Some(size), Some(name)) = (parts.next(), parts.next(), parts.next())
        else {
            panic!("tests/size_baseline.txt: malformed line {line:?}");
        };
        let size: usize = size
            .parse()
            .unwrap_or_else(|_| panic!("tests/size_baseline.txt: bad size in {line:?}"));
        baseline.insert(format!("{kind} {name}"), size);
    }

    let entry = |key: &str, size: usize| {
        let (kind, name) = key.split_once(' ').unwrap();
        format!("{kind} {size} {name}")
    };
    let budget = |key: &str| {
        if key.starts_with("file ") {
            format!("{FILE_BUDGET} non-test lines")
        } else {
            format!("{FUNCTION_BUDGET} lines")
        }
    };
    let mut problems = Vec::new();
    for (key, &size) in &current {
        match baseline.get(key) {
            None => problems.push(format!(
                "new: {key} is {size} lines, over the {} budget. Split it; \
                 if it must stay this size, add `{}` to the baseline.",
                budget(key),
                entry(key, size)
            )),
            Some(&allowed) if size > allowed => problems.push(format!(
                "grew: {key} is {size} lines, baseline {allowed}. Shrink it back; \
                 if the growth is deliberate, change its baseline line to `{}`.",
                entry(key, size)
            )),
            Some(&allowed) if size < allowed => problems.push(format!(
                "shrank: {key} is {size} lines, baseline {allowed}. Update the \
                 baseline downward: `{}`.",
                entry(key, size)
            )),
            Some(_) => {}
        }
    }
    for (key, &allowed) in &baseline {
        if !current.contains_key(key) {
            problems.push(format!(
                "under budget: {key} (baseline {allowed}) is now within the {} \
                 budget or gone. Delete its line `{}` from the baseline.",
                budget(key),
                entry(key, allowed)
            ));
        }
    }
    if !problems.is_empty() {
        let mut expected = String::from(BASELINE_HEADER);
        for (key, &size) in &current {
            expected.push_str(&entry(key, size));
            expected.push('\n');
        }
        panic!(
            "size budgets (docs/human/ARCHITECTURE.md, layering rule 5):\n  {}\n\n\
             tests/size_baseline.txt as it reads now (paste over the file):\n\n{expected}",
            problems.join("\n  ")
        );
    }
    println!(
        "size budgets: {} file(s) and {} function(s) over budget, none above baseline",
        current
            .keys()
            .filter(|key| key.starts_with("file "))
            .count(),
        current.keys().filter(|key| key.starts_with("fn ")).count()
    );
}

/// The comment block at the top of `tests/size_baseline.txt`.
const BASELINE_HEADER: &str = "\
# Size budget ratchet (tests/architecture.rs::size_budgets_ratchet).
# Every src/ file over 1,500 non-test lines and every non-test function
# over 150 lines, with its size today. Entries may only shrink or go away;
# the test prints this file's new contents whenever it must change.
#
#   file <non-test lines> <path>
#   fn <lines> <path>::<name>[#<nth occurrence in the file>]
";

/// Rough function lengths: a `fn` at indentation ≤ 4 runs to its matching
/// brace, with strings, chars, and comments blanked so their braces do not
/// count. A function under `#[cfg(test)]` is test code wherever it sits in
/// the file, so it is measured (to step over its body) and left out of the
/// function budget. The file budget still counts its lines: `non_test`
/// cuts only at `mod tests`.
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
        if !test_only(&lines[..i]) {
            out.push((name, j - i + 1));
        }
        i = j + 1;
    }
    out
}

/// Whether the item starting after `above` carries `#[cfg(test)]`: one of
/// the attribute lines directly over it says so. Doc comments are already
/// blank here, so blank lines between attributes are stepped over.
fn test_only(above: &[&str]) -> bool {
    above
        .iter()
        .rev()
        .map(|line| line.trim())
        .take_while(|line| line.is_empty() || line.starts_with("#["))
        .any(|line| line == "#[cfg(test)]")
}

#[test]
fn function_lengths_leave_out_test_only_functions() {
    let text = "fn kept() {\n    a();\n}\n\n\
        #[cfg(test)]\npub(crate) fn dropped() {\n    b();\n    c();\n}\n\n\
        /// Docs.\n#[cfg(test)]\n#[allow(dead_code)]\nfn also_dropped() {}\n\n\
        #[cfg(unix)]\nfn also_kept() {}\n";
    assert_eq!(
        function_lengths(text),
        vec![("kept".to_string(), 3), ("also_kept".to_string(), 1)]
    );
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
/// store, so every write must happen with the lock held: in a function
/// that took the lock earlier in its body, or in a method of an env guard
/// (`impl Drop for StoreEnv`, `StoreEnv::enter`), where every function that
/// names the guard took the lock before naming it. The scan reads code
/// tokens, so the lock named in a comment or a string does not count.
#[test]
fn store_env_writes_hold_the_lock() {
    let mut violations = Vec::new();
    let mut writes = 0;
    for (relative, text) in all_sources() {
        let (found, sites) = store_env_violations(&text);
        writes += sites;
        violations.extend(found.into_iter().map(|v| format!("{relative}: {v}")));
    }
    // Positive control: the unit tests that point the store elsewhere
    // write the variable dozens of times.
    assert!(
        writes >= 20,
        "the TOG_STORE scan found only {writes} writes; it is passing vacuously"
    );
    assert!(
        violations.is_empty(),
        "TOG_STORE written without STORE_ENV_LOCK held:\n  {}",
        violations.join("\n  ")
    );
}

/// What a `{` opened, for the TOG_STORE scan.
enum EnvScope {
    /// Index into the function table.
    Function(usize),
    /// The type an `impl` block is for.
    Impl(String),
    Block,
}

/// The TOG_STORE writes in `text` made without the lock held, and how many
/// writes there were.
fn store_env_violations(text: &str) -> (Vec<String>, usize) {
    let tokens = tokenize(text);
    let write_at = |i: usize| {
        (is_ident(tokens.get(i), "set_var") || is_ident(tokens.get(i), "remove_var"))
            && is_punct(tokens.get(i + 1), '(')
            && matches!(tokens.get(i + 2), Some(Token::Str(name)) if name == "TOG_STORE")
    };
    // Pass one finds the guard types: impls whose methods write the
    // variable. Pass two checks every write and every use of a guard.
    let mut guards: Vec<String> = Vec::new();
    let mut violations = Vec::new();
    let mut sites = 0;
    for pass in 0..2 {
        // (name, impl type, lock taken so far)
        let mut functions: Vec<(String, Option<String>, bool)> = Vec::new();
        let mut scopes: Vec<EnvScope> = Vec::new();
        let mut pending_fn: Option<String> = None;
        let mut pending_impl: Option<Option<String>> = None;
        for i in 0..tokens.len() {
            let current = scopes.iter().rev().find_map(|scope| match scope {
                EnvScope::Function(index) => Some(*index),
                _ => None,
            });
            match &tokens[i] {
                Token::Ident(word) if word == "fn" => {
                    if let Some(Token::Ident(name)) = tokens.get(i + 1) {
                        pending_fn = Some(name.clone());
                    }
                }
                Token::Ident(word) if word == "impl" => pending_impl = Some(None),
                Token::Ident(word) if pending_impl.is_some() && pending_fn.is_none() => {
                    pending_impl = Some(Some(word.clone()));
                }
                Token::Punct(';') => {
                    pending_fn = None;
                    pending_impl = None;
                }
                Token::Punct('{') => {
                    if let Some(name) = pending_fn.take() {
                        // `impl Trait` in a signature opens no impl block.
                        pending_impl = None;
                        let owner = scopes.iter().rev().find_map(|scope| match scope {
                            EnvScope::Impl(ty) => Some(ty.clone()),
                            EnvScope::Function(_) => Some(String::new()),
                            EnvScope::Block => None,
                        });
                        let owner = owner.filter(|ty| !ty.is_empty());
                        functions.push((name, owner, false));
                        scopes.push(EnvScope::Function(functions.len() - 1));
                    } else if let Some(ty) = pending_impl.take() {
                        scopes.push(EnvScope::Impl(ty.unwrap_or_default()));
                    } else {
                        scopes.push(EnvScope::Block);
                    }
                }
                Token::Punct('}') => {
                    scopes.pop();
                }
                _ => {}
            }
            let Some(index) = current else { continue };
            let (name, owner, locked) = &functions[index];
            if is_ident(tokens.get(i), "STORE_ENV_LOCK") {
                functions[index].2 = true;
            } else if write_at(i) {
                match owner {
                    Some(ty) if pass == 0 => {
                        if !guards.contains(ty) {
                            guards.push(ty.clone());
                        }
                    }
                    _ if pass == 0 => {}
                    _ if *locked => sites += 1,
                    Some(ty) if guards.contains(ty) => sites += 1,
                    _ => {
                        sites += 1;
                        violations
                            .push(format!("fn {name} writes TOG_STORE before taking the lock"));
                    }
                }
            } else if pass == 1 {
                if let Some(Token::Ident(word)) = tokens.get(i) {
                    if guards.contains(word) && owner.as_ref() != Some(word) && !*locked {
                        violations.push(format!(
                            "fn {name} uses the TOG_STORE guard {word} before taking the lock"
                        ));
                    }
                }
            }
        }
    }
    (violations, sites)
}

#[test]
fn the_store_env_scan_sees_through_comments_and_guards() {
    let unlocked = "// STORE_ENV_LOCK is held by the caller\n\
        fn t() { let s = \"STORE_ENV_LOCK\"; std::env::set_var(\"TOG_STORE\", p); }";
    assert_eq!(
        store_env_violations(unlocked).0,
        ["fn t writes TOG_STORE before taking the lock"]
    );
    let late = "fn t() { env::remove_var(\"TOG_STORE\"); let _l = STORE_ENV_LOCK.lock(); }";
    assert_eq!(
        store_env_violations(late).0,
        ["fn t writes TOG_STORE before taking the lock"]
    );
    let guarded = "struct StoreEnv(Option<OsString>);\n\
        impl StoreEnv { fn enter(p: &Path) -> Self { std::env::set_var(\"TOG_STORE\", p); Self(None) } }\n\
        impl Drop for StoreEnv { fn drop(&mut self) { std::env::remove_var(\"TOG_STORE\"); } }\n\
        fn good() { let _l = STORE_ENV_LOCK.lock(); let _e = StoreEnv::enter(p); }\n\
        fn bad() { let _e = StoreEnv::enter(p); }";
    let (found, sites) = store_env_violations(guarded);
    assert_eq!(
        found,
        ["fn bad uses the TOG_STORE guard StoreEnv before taking the lock"]
    );
    assert_eq!(sites, 2);
    let nested = "fn t() { let _l = STORE_ENV_LOCK.lock();\n\
        struct G; impl Drop for G { fn drop(&mut self) { std::env::remove_var(\"TOG_STORE\"); } }\n\
        std::env::set_var(\"TOG_STORE\", p); let _g = G; }";
    assert_eq!(store_env_violations(nested), (Vec::<String>::new(), 2));
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
/// Two spellings are tog's own narration: `eprintln!`, and a handle from
/// `io::stderr()` written with `writeln!`. `eprint!` is the verbatim
/// pass-through of a subprocess's captured output and of an
/// already-rendered usage error, neither of which takes a `tog:` prefix.
/// A lower layer that renders its own narration into a `Write` gets its
/// handle from `ui::narration()`.
///
/// The `io::stderr()` sites below are not narration, each for the reason
/// given. The match is on the line's code, so a second site in a listed
/// file is still reported, and a listed site that disappears fails the
/// test until its row goes too.
const STDERR_HANDLES: &[(&str, &str, &str)] = &[
    (
        "src/kernel/supervise.rs",
        "let _ = io::stderr().write_all(bytes);",
        "verbatim relay of a supervised child's stderr",
    ),
    (
        "src/kernel/sandbox.rs",
        "&mut io::stderr(),",
        "scrubbed relay of a sandboxed build's stderr",
    ),
    (
        "src/commands/deps.rs",
        "if !(io::stderr().is_terminal() && io::stdin().is_terminal()) {",
        "a terminal test; writes nothing",
    ),
    (
        "src/commands/deps.rs",
        "let mut stderr = io::stderr();",
        "the interactive which-registry prompt, a question rather than narration",
    ),
];

/// Does this line of code write tog's narration to stderr directly? The
/// comment part of the line is ignored; `.stderr(…)` (a `Command` method)
/// and `child.stderr` (a field) are not the process's stderr.
fn writes_stderr(line: &str) -> bool {
    let code = match comment_text(line) {
        Some(comment) => &line[..line.len() - comment.len()],
        None => line,
    };
    code.contains("eprintln!")
        || code.match_indices("stderr()").any(|(at, _)| {
            !code[..at]
                .chars()
                .next_back()
                .is_some_and(|c| c == '.' || is_ident_char(c))
        })
}

#[test]
fn narration_goes_through_kernel_ui() {
    let mut violations = Vec::new();
    let mut listed = vec![false; STDERR_HANDLES.len()];
    for (relative, text) in all_sources() {
        if !relative.starts_with("src/") || relative == "src/kernel/ui.rs" {
            continue;
        }
        for (index, line) in outside_test_modules(&text).lines().enumerate() {
            if !writes_stderr(line) {
                continue;
            }
            match STDERR_HANDLES
                .iter()
                .position(|(file, code, _)| *file == relative && line.trim() == *code)
            {
                Some(row) => listed[row] = true,
                None => violations.push(format!("{relative}:{}: {}", index + 1, line.trim())),
            }
        }
    }
    let stale: Vec<_> = STDERR_HANDLES
        .iter()
        .zip(&listed)
        .filter(|(_, seen)| !**seen)
        .map(|((file, code, _), _)| format!("{file}: {code}"))
        .collect();
    assert!(
        stale.is_empty(),
        "STDERR_HANDLES rows that match nothing (delete them):\n  {}",
        stale.join("\n  ")
    );
    assert!(
        violations.is_empty(),
        "stderr written outside kernel::ui (use ui::note for progress, \
         ui::warning for an advisory, ui::error for a failure, \
         ui::narration for a report rendered into a writer):\n  {}",
        violations.join("\n  ")
    );
}

#[test]
fn the_stderr_scan_sees_every_spelling() {
    for line in [
        "eprintln!(\"tog: x\");",
        "let mut out = io::stderr().lock();",
        "writeln!(std::io::stderr(), \"x\")?;",
        "let e = stderr(); // after `use std::io::stderr`",
    ] {
        assert!(writes_stderr(line), "{line}");
    }
    for line in [
        "eprint!(\"{captured}\");",
        "command.stderr(Stdio::piped());",
        "let pipe = child.stderr.take();",
        "// io::stderr() is locked by ui::narration",
        "let s = my_stderr();",
    ] {
        assert!(!writes_stderr(line), "{line}");
    }
}

/// The part of a file before its first `#[cfg(test)]` module. Unlike
/// `non_test`, this finds a test module under any name (`mod tests`,
/// `mod fixture_tests`), which is what a scan for test-only output
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

/// One Rust token, with comments and whitespace gone and every literal
/// collapsed to `Lit`, so a scan cannot be fooled by `.status /* c */ ()`,
/// by a call split across lines, or by a string that happens to spell code.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Ident(String),
    Punct(char),
    /// A string literal, with its contents as written (escapes unprocessed).
    Str(String),
    Lit,
}

fn tokenize(text: &str) -> Vec<Token> {
    let chars: Vec<char> = text.chars().collect();
    let n = chars.len();
    let mut out = Vec::new();
    let mut i = 0;
    while i < n {
        let c = chars[i];
        if c.is_whitespace() {
            i += 1;
        } else if c == '/' && i + 1 < n && chars[i + 1] == '/' {
            while i < n && chars[i] != '\n' {
                i += 1;
            }
        } else if c == '/' && i + 1 < n && chars[i + 1] == '*' {
            // Block comments nest in Rust.
            let mut depth = 0;
            while i < n {
                if chars[i] == '/' && i + 1 < n && chars[i + 1] == '*' {
                    depth += 1;
                    i += 2;
                } else if chars[i] == '*' && i + 1 < n && chars[i + 1] == '/' {
                    depth -= 1;
                    i += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    i += 1;
                }
            }
        } else if let Some((start, end, close)) = raw_string_end(&chars, i) {
            out.push(Token::Str(chars[start..end.min(n)].iter().collect()));
            i = close;
        } else if c == '"' || (c == 'b' && i + 1 < n && chars[i + 1] == '"') {
            i += if c == 'b' { 2 } else { 1 };
            let start = i;
            while i < n && chars[i] != '"' {
                if chars[i] == '\\' {
                    i += 1;
                }
                i += 1;
            }
            out.push(Token::Str(chars[start..i.min(n)].iter().collect()));
            i += 1;
        } else if c == '\'' || (c == 'b' && i + 1 < n && chars[i + 1] == '\'') {
            let start = if c == 'b' { i + 1 } else { i };
            // A char literal closes within a few characters; otherwise this
            // quote starts a lifetime or label, which is an identifier here.
            let close = if start + 1 < n && chars[start + 1] == '\\' {
                (start + 2..n.min(start + 12)).find(|&j| chars[j] == '\'')
            } else if start + 2 < n && chars[start + 2] == '\'' {
                Some(start + 2)
            } else {
                None
            };
            match close {
                Some(j) => {
                    out.push(Token::Lit);
                    i = j + 1;
                }
                None => {
                    i = start + 1;
                    while i < n && (chars[i].is_alphanumeric() || chars[i] == '_') {
                        i += 1;
                    }
                }
            }
        } else if c.is_alphabetic() || c == '_' {
            // A raw identifier `r#spawn` is the identifier `spawn`.
            if c == 'r'
                && i + 2 < n
                && chars[i + 1] == '#'
                && (chars[i + 2].is_alphabetic() || chars[i + 2] == '_')
            {
                i += 2;
            }
            let start = i;
            while i < n && (chars[i].is_alphanumeric() || chars[i] == '_') {
                i += 1;
            }
            out.push(Token::Ident(chars[start..i].iter().collect()));
        } else if c.is_ascii_digit() {
            while i < n && (chars[i].is_alphanumeric() || chars[i] == '_' || chars[i] == '.') {
                // `0..n` is a range, not a float.
                if chars[i] == '.' && i + 1 < n && chars[i + 1] == '.' {
                    break;
                }
                i += 1;
            }
            out.push(Token::Lit);
        } else {
            out.push(Token::Punct(c));
            i += 1;
        }
    }
    out
}

/// Where the contents of a raw string literal (`r"…"`, `r#"…"#`, `br"…"`)
/// starting at `i` begin and end, and where the literal ends, if one does.
fn raw_string_end(chars: &[char], i: usize) -> Option<(usize, usize, usize)> {
    let n = chars.len();
    let mut j = i;
    if chars[j] == 'b' {
        j += 1;
    }
    if j >= n || chars[j] != 'r' {
        return None;
    }
    if i > 0 && (chars[i - 1].is_alphanumeric() || chars[i - 1] == '_') {
        return None;
    }
    j += 1;
    let mut hashes = 0;
    while j < n && chars[j] == '#' {
        hashes += 1;
        j += 1;
    }
    if j >= n || chars[j] != '"' {
        return None;
    }
    j += 1;
    let start = j;
    while j < n {
        if chars[j] == '"' && (1..=hashes).all(|k| j + k < n && chars[j + k] == '#') {
            return Some((start, j, j + 1 + hashes));
        }
        j += 1;
    }
    Some((start, n, n))
}

fn is_ident(token: Option<&Token>, name: &str) -> bool {
    matches!(token, Some(Token::Ident(text)) if text == name)
}

fn is_punct(token: Option<&Token>, c: char) -> bool {
    token == Some(&Token::Punct(c))
}

/// Production tokens of a file, each tagged with the innermost named `fn`
/// around it. Items under `#[cfg(test)]` (test modules and test-only
/// helpers) are dropped whole.
fn production_tokens(text: &str) -> Vec<(Token, String)> {
    let tokens = tokenize(text);
    let mut out = Vec::new();
    // (fn name, brace depth its body opened at)
    let mut functions: Vec<(String, usize)> = Vec::new();
    let mut pending_fn: Option<String> = None;
    let mut depth = 0usize;
    let mut i = 0;
    while i < tokens.len() {
        // `# [ cfg ( test ) ]` drops the next item: through its matching
        // brace, or through the `;` or `,` that ends an item, field or
        // expression without a body. A `}` that closes the enclosing block
        // ends it too and is kept.
        if is_punct(tokens.get(i), '#')
            && is_punct(tokens.get(i + 1), '[')
            && is_ident(tokens.get(i + 2), "cfg")
            && is_punct(tokens.get(i + 3), '(')
            && is_ident(tokens.get(i + 4), "test")
            && is_punct(tokens.get(i + 5), ')')
            && is_punct(tokens.get(i + 6), ']')
        {
            let mut j = i + 7;
            let mut braces = 0usize;
            let mut groups = 0usize;
            let mut consumed_close = true;
            while j < tokens.len() {
                let arrow = j > 0 && tokens[j - 1] == Token::Punct('-');
                match &tokens[j] {
                    Token::Punct('{') => braces += 1,
                    Token::Punct('}') if braces == 0 => {
                        consumed_close = false;
                        break;
                    }
                    Token::Punct('}') => {
                        braces -= 1;
                        if braces == 0 && groups == 0 {
                            break;
                        }
                    }
                    Token::Punct('(' | '[') if braces == 0 => groups += 1,
                    Token::Punct(')' | ']') if braces == 0 => groups = groups.saturating_sub(1),
                    Token::Punct('<') if braces == 0 => groups += 1,
                    Token::Punct('>') if braces == 0 && !arrow => groups = groups.saturating_sub(1),
                    Token::Punct(';' | ',') if braces == 0 && groups == 0 => break,
                    _ => {}
                }
                j += 1;
            }
            i = if consumed_close { j + 1 } else { j };
            continue;
        }
        let token = tokens[i].clone();
        match &token {
            Token::Ident(word) if word == "fn" => {
                if let Some(Token::Ident(name)) = tokens.get(i + 1) {
                    pending_fn = Some(name.clone());
                }
            }
            Token::Punct(';') if pending_fn.is_some() => {
                // A body-less signature (a trait method declaration).
                if functions.last().map(|(_, d)| *d) != Some(depth) {
                    pending_fn = None;
                }
            }
            Token::Punct('{') => {
                depth += 1;
                if let Some(name) = pending_fn.take() {
                    functions.push((name, depth));
                }
            }
            Token::Punct('}') => {
                if functions.last().is_some_and(|(_, d)| *d == depth) {
                    functions.pop();
                }
                depth = depth.saturating_sub(1);
            }
            _ => {}
        }
        let owner = functions
            .last()
            .map(|(name, _)| name.clone())
            .unwrap_or_default();
        out.push((token, owner));
        i += 1;
    }
    out
}

/// The names a file uses for `ty`: `ty` itself plus every `ty as Alias`
/// import, so `use std::process::Command as P; P::spawn(&mut c)` is seen,
/// and every `type Alias = path::to::ty;`.
///
/// The limit: one step only. An alias of an alias (`type A = ty;
/// type B = A;`, or `use` of a name another file aliased) is not followed,
/// so `B` is not a name for `ty` here. Nothing in `src/` spells a scanned
/// type that way.
fn names_for(tokens: &[(Token, String)], ty: &str) -> Vec<String> {
    let mut names = vec![ty.to_string()];
    for i in 0..tokens.len() {
        if is_ident(token_at(tokens, i), ty) && is_ident(token_at(tokens, i + 1), "as") {
            if let Some(Token::Ident(alias)) = token_at(tokens, i + 2) {
                names.push(alias.clone());
            }
        }
        // `type Alias = a::b::ty;`: the path's last segment, right before
        // the `;`, is the type. (`type R = Result<ty, E>;` ends in `>`.)
        if is_ident(token_at(tokens, i), "type") && is_punct(token_at(tokens, i + 2), '=') {
            let end = (i + 3..tokens.len()).find(|&j| is_punct(token_at(tokens, j), ';'));
            if let (Some(Token::Ident(alias)), Some(end)) = (token_at(tokens, i + 1), end) {
                if is_ident(token_at(tokens, end - 1), ty) {
                    names.push(alias.clone());
                }
            }
        }
    }
    names
}

/// `Name :: method` where `Name` is one of `types`: a path call
/// (`Command::spawn(&mut c)`, `Store::activity(&store, m)`) or a function
/// value passed on without calling it.
fn path_call(tokens: &[(Token, String)], i: usize, types: &[String], methods: &[&str]) -> bool {
    matches!(token_at(tokens, i), Some(Token::Ident(name)) if types.contains(name))
        && is_punct(token_at(tokens, i + 1), ':')
        && is_punct(token_at(tokens, i + 2), ':')
        && methods
            .iter()
            .any(|method| is_ident(token_at(tokens, i + 3), method))
}

/// `.method(` on any receiver.
fn method_call(tokens: &[(Token, String)], i: usize, methods: &[&str]) -> bool {
    is_punct(token_at(tokens, i), '.')
        && methods
            .iter()
            .any(|method| is_ident(token_at(tokens, i + 1), method))
        && is_punct(token_at(tokens, i + 2), '(')
}

const SPAWNS: &[&str] = &["status", "output", "spawn"];

/// The names one file gives the scanned types, aliases included.
struct Names {
    commands: Vec<String>,
    stores: Vec<String>,
    activities: Vec<String>,
}

impl Names {
    fn of(tokens: &[(Token, String)]) -> Names {
        Names {
            commands: names_for(tokens, "Command"),
            stores: names_for(tokens, "Store"),
            activities: names_for(tokens, "StoreActivity"),
        }
    }
}

/// A raw child: `.status()`/`.output()`/`.spawn()` (no arguments, so
/// `supervise::status(cmd, activity)` is not one), or a `Command` path call
/// under any alias.
fn raw_child_at(tokens: &[(Token, String)], i: usize, names: &Names) -> bool {
    (method_call(tokens, i, SPAWNS) && is_punct(token_at(tokens, i + 3), ')'))
        || path_call(tokens, i, &names.commands, SPAWNS)
}

/// A lease taken: `.activity(`/`.try_activity_exclusive(` (or its
/// `_unchecked` form), the same as a `Store` path, or
/// `StoreActivity::acquire`/`try_exclusive`, under any alias.
fn lease_at(tokens: &[(Token, String)], i: usize, names: &Names) -> bool {
    const STORE: &[&str] = &[
        "activity",
        "try_activity_shared",
        "try_activity_exclusive",
        "try_activity_exclusive_unchecked",
    ];
    method_call(tokens, i, STORE)
        || path_call(tokens, i, &names.stores, STORE)
        || path_call(
            tokens,
            i,
            &names.activities,
            &["acquire", "try_shared", "try_exclusive"],
        )
}

/// Per-function counts of `(file, fn)` sites matching `hit` at a token.
fn count_sites(
    skip: &[&str],
    hit: fn(&[(Token, String)], usize, &Names) -> bool,
) -> Vec<(String, String, usize)> {
    let mut counts: Vec<(String, String, usize)> = Vec::new();
    for (relative, text) in all_sources() {
        if !relative.starts_with("src/") || skip.contains(&relative.as_str()) {
            continue;
        }
        let tokens = production_tokens(&text);
        let names = Names::of(&tokens);
        for index in 0..tokens.len() {
            if !hit(&tokens, index, &names) {
                continue;
            }
            let owner = tokens[index].1.clone();
            match counts
                .iter_mut()
                .find(|(file, function, _)| *file == relative && *function == owner)
            {
                Some(entry) => entry.2 += 1,
                None => counts.push((relative.clone(), owner, 1)),
            }
        }
    }
    counts.sort();
    counts
}

fn expected_sites(list: &[(&str, &str, usize)]) -> Vec<(String, String, usize)> {
    let mut expected: Vec<(String, String, usize)> = list
        .iter()
        .map(|(file, function, count)| (file.to_string(), function.to_string(), *count))
        .collect();
    expected.sort();
    expected
}

fn token_at(tokens: &[(Token, String)], index: usize) -> Option<&Token> {
    tokens.get(index).map(|(token, _)| token)
}

/// A child process that reads or writes a store path runs through
/// `kernel::supervise` with the caller's activity lease, so protection is
/// provable at the call site. The only raw `.status()`, `.output()` or
/// `.spawn()` calls left in production code are counted here, per function;
/// each touches no store path, and the comment above each group says why.
/// A new raw child, even in a listed function, fails until it borrows a
/// lease or is added here with a reason.
const RAW_CHILD_SITES: &[(&str, &str, usize)] = &[
    // `None` arm of `Option<&StoreActivity>`: no store is involved.
    ("src/comforter/mod.rs", "clone_tree_for", 3),
    ("src/kernel/archive.rs", "list_names", 1),
    ("src/kernel/archive.rs", "status_for", 1),
    ("src/kernel/sandbox.rs", "run_preflight", 2),
    // The one unmanaged sandbox spawn: the `None` arm of every sandbox
    // entry point, for callers that consume no store.
    ("src/kernel/sandbox.rs", "spawn_unmanaged", 1),
    // Host probes, and the downloaded tog's `--version` before it is
    // installed.
    ("src/commands/selfupdate.rs", "smoke_test", 1),
    ("src/tailors/dotnet/mod.rs", "invoking_uid", 1),
    ("src/tailors/python/pypi.rs", "detect_host_glibc", 1),
    // The resolution relay starts the tool inside the resolution sandbox,
    // where no store is mounted writable and there is no lease to borrow.
    ("src/kernel/resolve/relay.rs", "spawn_tool", 1),
];

/// The functions allowed to take an activity lease (`.activity(`,
/// `try_activity_exclusive`, `StoreActivity::acquire`/`try_exclusive`),
/// with how many times. Each is an operation boundary: it owns the work its
/// lease protects and passes that lease down. A helper that receives a
/// store from a caller already holding a lease must take the caller's
/// `&StoreActivity` instead, because a nested acquisition under the
/// thread's own exclusive lease is refused.
const LEASE_BOUNDARIES: &[(&str, &str, usize)] = &[
    // The primitives themselves.
    ("src/kernel/store/mod.rs", "activity", 1),
    ("src/kernel/store/mod.rs", "try_activity_exclusive", 1),
    ("src/kernel/store/mod.rs", "try_activity_shared", 1),
    // `existing` with a shared lease, for a reader that only locates the
    // store and holds it while it reads (the local Rust tree cache, #434).
    ("src/kernel/store/mod.rs", "existing_shared", 1),
    // The one primitive that does not validate the format marker.
    (
        "src/kernel/store/mod.rs",
        "try_activity_exclusive_unchecked",
        1,
    ),
    // Command entry points: the shared lease every tailor command borrows
    // (`Context`), and the commands that open the store without one.
    ("src/kernel/context.rs", "open_with_project_dir", 1),
    ("src/commands/doctor.rs", "run", 1),
    // `store roots`: the lease its diagnostic read borrows.
    ("src/commands/store.rs", "list_roots", 1),
    ("src/commands/gc.rs", "run", 1),
    // `gc --reset` opens a store `run` cannot: one tog refuses to read.
    ("src/commands/gc.rs", "reset", 1),
    // `x --clean`, once per environment, on the store that owns it.
    ("src/commands/x/cleanup.rs", "clean_lease", 1),
    ("src/kernel/gc/mod.rs", "collect", 1),
    // Public root-registry calls for callers holding no lease (tests and
    // library users). Each has a `_with_activity` form that production uses.
    ("src/kernel/store/roots.rs", "register_root_record", 1),
    ("src/kernel/store/roots.rs", "register_root_from_project", 1),
    ("src/kernel/store/roots.rs", "remove_root_entry", 1),
    ("src/kernel/store/roots.rs", "forget_root", 1),
    // Compiled only under `cfg(test)` (declared so in kernel/mod.rs): a
    // lease on a scratch directory for tests with no store.
    ("src/kernel/testutil.rs", "detached_lease", 1),
];

/// A `Store` made without reading its format marker: the struct written
/// out (`Store { root }`) or `Store::handle(`, under any `use` or `type`
/// alias, and `Self { root }` / `Self::handle(` in a file with an
/// `impl Store` or `impl Trait for Store` block (the scan does not track
/// which `impl` a function is in, so `Self` counts anywhere in such a
/// file). Its limit: an alias of an alias (`use Store as A;` then
/// `type B = A;`) is not followed, so `B { root }` would go unseen. Extend
/// it if a real miss appears.
fn unchecked_store_at(tokens: &[(Token, String)], i: usize, names: &Names) -> bool {
    let mut stores = names.stores.clone();
    if is_ident(token_at(tokens, i), "Self") {
        let implements_store = (0..tokens.len()).any(|j| {
            (is_ident(token_at(tokens, j), "impl") || is_ident(token_at(tokens, j), "for"))
                && matches!(token_at(tokens, j + 1), Some(Token::Ident(name)) if names.stores.contains(name))
                && is_punct(token_at(tokens, j + 2), '{')
        });
        if implements_store {
            stores.push("Self".into());
        }
    }
    path_call(tokens, i, &stores, &["handle"])
        || (matches!(token_at(tokens, i), Some(Token::Ident(name)) if stores.contains(name))
            && is_punct(token_at(tokens, i + 1), '{')
            && is_ident(token_at(tokens, i + 2), "root"))
}

/// The seven functions allowed to make a `Store` without validating its
/// format marker, with how many times. Everything else goes through `Store::open`,
/// `Store::existing` or `Store::open_at`, which refuse a store this tog
/// does not read. A store made here is still validated before any record
/// is read, because every lease but `try_activity_exclusive_unchecked`
/// checks the marker once it is held. That last part is not something this
/// count proves: it is why the readers take a `&StoreActivity`, and why
/// `store_children_borrow_the_callers_lease` lists who may take a lease.
const UNCHECKED_STORES: &[(&str, &str, usize)] = &[
    // The constructors: `open_root` and `existing` have just validated or
    // written the marker, and `handle` is the unchecked form itself.
    ("src/kernel/store/mod.rs", "open_root", 1),
    ("src/kernel/store/mod.rs", "existing", 1),
    ("src/kernel/store/mod.rs", "handle", 1),
    // `gc --reset` empties a store tog refuses to read, and never reads a
    // record of it.
    ("src/commands/gc.rs", "reset", 1),
    // A store named by an x environment's own records, which may not be the
    // configured one: by its request record here, and by the object paths
    // in its closure in `store_from_object_path`. `x --clean` leases either
    // (validated) before it reads or removes anything.
    ("src/commands/x/cleanup.rs", "originating_store_in", 1),
    ("src/comforter/mod.rs", "store_from_object_path", 1),
    // Names an x environment's directory from the store's path alone, and
    // reads nothing in the store.
    ("src/commands/x/mod.rs", "environment_name", 1),
];

#[test]
fn stores_are_made_through_a_checked_constructor() {
    assert_eq!(
        count_sites(&[], unchecked_store_at),
        expected_sites(UNCHECKED_STORES),
        "a `Store` is made without validating its format marker; use \
         `Store::open`/`existing`/`open_at` (or, for a store that is leased \
         before any record is read, count it in UNCHECKED_STORES with the \
         reason)"
    );
}

#[test]
fn store_children_borrow_the_callers_lease() {
    assert_eq!(
        count_sites(&["src/kernel/supervise.rs"], raw_child_at),
        expected_sites(RAW_CHILD_SITES),
        "a production child runs without the caller's activity lease; pass \
         `&StoreActivity` to `kernel::supervise` (or, for a child that touches \
         no store path, count it in RAW_CHILD_SITES with the reason)"
    );
    assert_eq!(
        count_sites(&["src/kernel/activity.rs"], lease_at),
        expected_sites(LEASE_BOUNDARIES),
        "an activity lease is taken outside the reviewed operation boundaries; \
         take the caller's `&StoreActivity` instead (or, for a new operation \
         boundary, count it in LEASE_BOUNDARIES)"
    );
}

/// Every non-private `kernel::supervise` function (`pub`, `pub(crate)`,
/// `pub(super)`, `pub(in ...)`) that starts a `Command` is
/// fenced. Either it is a `local_*` form whose first statement is the
/// resolver tripwire, so a dependency tool is refused before anything
/// spawns, or it is an unrestricted primitive that clippy refuses outside
/// the reviewed sites (`disallowed-methods` in `clippy.toml`) and that has
/// a `local_*` form beside it. A new spawn function that is neither would
/// let a resolver start outside `kernel::resolve`'s door unseen.
#[test]
fn every_public_supervise_spawn_is_fenced() {
    let root = repo();
    let supervise = fs::read_to_string(root.join("src/kernel/supervise.rs")).unwrap();
    let clippy = fs::read_to_string(root.join("clippy.toml")).unwrap();
    // The scan's own control: every visibility wider than private counts.
    let sample = "\npub fn a(c: &mut Command) {\n}\n\npub(crate) fn b(c: &mut Command) {\n}\n\
                  \npub(super) fn c(c: &mut Command) {\n}\n\npub(in crate::kernel) fn d(c: &mut Command) {\n}\n\
                  \nfn private(c: &mut Command) {\n}\n";
    let sampled: Vec<String> = visible_command_fns(sample)
        .into_iter()
        .map(|(name, _)| name)
        .collect();
    assert_eq!(sampled, ["a", "b", "c", "d"]);
    let spawners = visible_command_fns(&supervise);
    let names: Vec<&str> = spawners.iter().map(|(name, _)| name.as_str()).collect();
    // Positive control: the scan sees today's three primitives, so a
    // renamed or reformatted file fails here instead of passing with
    // nothing to check.
    for primitive in ["status", "status_with_stderr", "output"] {
        assert!(
            names.contains(&primitive),
            "the supervise scan no longer sees `{primitive}` (found {names:?}); it is passing vacuously"
        );
    }
    let mut unfenced = Vec::new();
    for (name, body) in &spawners {
        let fenced = match name.strip_prefix("local_") {
            Some(_) => body
                .trim_start()
                .starts_with("refuse_resolver(command, activity)?;"),
            None => {
                clippy.contains(&format!("path = \"tog::kernel::supervise::{name}\""))
                    && names.contains(&format!("local_{name}").as_str())
            }
        };
        if !fenced {
            unfenced.push(name.as_str());
        }
    }
    assert!(
        unfenced.is_empty(),
        "non-private supervise spawn functions outside the resolution fence: {unfenced:?}. \
         A `local_*` form must start with `refuse_resolver(command, activity)?;`; any other \
         must be listed in clippy.toml's disallowed-methods and have a `local_*` form"
    );
}

/// The name and body of every non-private top-level function in `text`
/// (`pub`, `pub(crate)`, `pub(super)`, `pub(in ...)`) whose signature
/// mentions `Command`.
fn visible_command_fns(text: &str) -> Vec<(String, String)> {
    let mut found = Vec::new();
    for (index, _) in text.match_indices("\npub") {
        let rest = &text[index + "\npub".len()..];
        let rest = match rest.strip_prefix('(') {
            Some(inner) => match inner.find(')') {
                Some(close) => &inner[close + 1..],
                None => continue,
            },
            None => rest,
        };
        let Some(rest) = rest.strip_prefix(" fn ") else {
            continue;
        };
        let name: String = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        let open = rest.find('{').unwrap();
        if !rest[..open].contains("Command") {
            continue;
        }
        let body = &rest[open + 1..open + rest[open..].find("\n}\n").unwrap()];
        found.push((name, body.to_string()));
    }
    found
}

/// The functions of `text` with a site `hit` finds, one entry per site.
fn fixture_owners(text: &str, hit: fn(&[(Token, String)], usize, &Names) -> bool) -> Vec<String> {
    let tokens = production_tokens(text);
    let names = Names::of(&tokens);
    (0..tokens.len())
        .filter(|&i| hit(&tokens, i, &names))
        .map(|i| tokens[i].1.clone())
        .collect()
}

/// Every spelling the scan must see through, and the ones it must not count.
#[test]
fn the_scan_sees_every_spelling() {
    let children = "use std::process::Command as P;\n\
        fn comment() { c.status /* c */ (); }\n\
        fn line_break() { c\n  .output(\n  ); let s = \".spawn()\"; }\n\
        fn raw_ident() { c.r#spawn(); }\n\
        fn path_call() { std::process::Command::spawn(&mut c); }\n\
        fn alias() { P::r#output(&mut c); }\n\
        fn supervised() { supervise::status(&mut c, activity); }\n\
        #[cfg(test)]\nfn test_only() { c.spawn(); }";
    assert_eq!(
        fixture_owners(children, raw_child_at),
        ["comment", "line_break", "raw_ident", "path_call", "alias"]
    );

    let leases = "use crate::kernel::store::Store as S;\n\
        use crate::kernel::activity::StoreActivity as Lease;\n\
        fn method() { let x = 'a'; store . activity (m); }\n\
        fn raw_ident() { store.r#try_activity_exclusive(); }\n\
        fn path_call() { Store::activity(&store, m); }\n\
        fn alias() { S::activity(&store, m); }\n\
        fn value() { let f = S::try_activity_exclusive; }\n\
        fn acquire() { Lease::acquire(root, m); StoreActivity::try_exclusive(root); }\n\
        fn borrowed() { store.require_activity(activity, \"x\"); let activity = activity; }";
    assert_eq!(
        fixture_owners(leases, lease_at),
        [
            "method",
            "raw_ident",
            "path_call",
            "alias",
            "value",
            "acquire",
            "acquire"
        ]
    );

    let stores = "use crate::kernel::store::Store as S;\n\
        type Mine = crate::kernel::store::Store;\n\
        type Maybe = Option<Store>;\n\
        impl Store {\n\
        fn literal() -> Store { Store { root } }\n\
        fn spaced() -> Store { store::Store {\n    root: path.into(),\n} }\n\
        fn self_literal() -> Self { Self { root } }\n\
        fn self_handle() -> Self { Self::handle(root) }\n\
        }\n\
        fn alias() { S { root }; }\n\
        fn type_alias() { Mine { root }; Mine::handle(root); }\n\
        fn handle() { Store::handle(root); let f = S::handle; }\n\
        fn checked() -> io::Result<Store> { Store::open_at(root) }\n\
        fn other() { Maybe::handle(root); Other { root }; let s = \"Store { root }\"; }\n\
        #[cfg(test)]\nfn test_only() { Store { root }; }";
    assert_eq!(
        fixture_owners(stores, unchecked_store_at),
        [
            "literal",
            "spaced",
            "self_literal",
            "self_handle",
            "alias",
            "type_alias",
            "type_alias",
            "handle",
            "handle"
        ]
    );
    // The stated limit: an alias of an alias is not followed.
    let chained = "type A = Store;\ntype B = A;\n\
        fn first() { A { root }; }\nfn second() { B { root }; }";
    assert_eq!(fixture_owners(chained, unchecked_store_at), ["first"]);
    let trait_impl = "impl From<PathBuf> for Store {\n\
        fn from(root: PathBuf) -> Self { Self { root } }\n\
        }";
    assert_eq!(fixture_owners(trait_impl, unchecked_store_at), ["from"]);
    // `Self` in a file with no `impl Store` is some other type's.
    let elsewhere = "use crate::kernel::store::Store;\n\
        impl Project { fn new() -> Self { Self { root } } }\n\
        fn walk() { for store in stores { Self { root }; } }";
    assert!(fixture_owners(elsewhere, unchecked_store_at).is_empty());
}

/// Every word that names a tailor: its id and lock ecosystem, and the
/// command-line word and cache prefix of its registry tool. Read from the
/// registry, so a new tailor is covered without editing this test.
fn tailor_words() -> Vec<String> {
    let mut words: Vec<String> = Vec::new();
    for tailor in tog::tailors::registry() {
        words.push(tailor.id().into());
        words.push(tailor.lock_ecosystem().into());
        if let Ok(tool) = tailor.registry_tool() {
            words.push(tool.spelling().into());
            words.push(tool.cache_prefix().into());
        }
    }
    words.sort();
    words.dedup();
    words
}

/// Does a string literal name one of `words`: the whole literal, or, in a
/// literal without whitespace (a name or path, not prose), one `/`
/// component up to its first dot (`.tog/closures/dotnet.json`,
/// `python.json`)? Prose that mentions a name is not a match.
fn names_a_word(literal: &str, words: &[String]) -> bool {
    let named = |text: &str| words.iter().any(|word| word == text);
    named(literal)
        || (!literal.chars().any(char::is_whitespace)
            && literal
                .split('/')
                .any(|part| named(part.split('.').next().unwrap_or(part))))
}

/// One naming site kind: (file, function, literal as written, count).
type LiteralSite = (String, String, String, usize);

/// Counts of string literals in `text` that name one of `words`
/// (`names_a_word`), per function and literal, outside `#[cfg(test)]`
/// items.
fn literal_sites(relative: &str, text: &str, words: &[String]) -> Vec<LiteralSite> {
    let mut counts: Vec<LiteralSite> = Vec::new();
    for (token, owner) in production_tokens(text) {
        let Token::Str(literal) = &token else {
            continue;
        };
        if !names_a_word(literal, words) {
            continue;
        }
        match counts
            .iter_mut()
            .find(|(_, function, text, _)| *function == owner && text == literal)
        {
            Some(entry) => entry.3 += 1,
            None => counts.push((relative.to_string(), owner, literal.clone(), 1)),
        }
    }
    counts
}

/// The command-file literals that still name a tailor, per function and
/// literal, with how many times, each row owned by the open issue that
/// removes it. The table only shrinks: the counts must match exactly, so
/// the fix that removes a literal also removes its row, and a new literal
/// fails even in a listed function, including a different name swapped in
/// for a listed one.
const TAILOR_NAMING_DEBT: &[(&str, &str, &str, usize)] = &[];

/// A command reaches an ecosystem through the `Tailor` trait and the
/// registry, never by spelling its name: a `"python"` or `"npm"` literal
/// in `src/commands/` is a branch or lookup the import scan above cannot
/// see, and it drifts back into tailor-specific code (layering rule 3).
/// Text that merely mentions a tailor inside a longer message is not a
/// match; only a literal that *is* the name, or names it as a path
/// component, counts.
#[test]
fn commands_do_not_name_tailors_by_string() {
    let words = tailor_words();
    let mut found: Vec<LiteralSite> = all_sources()
        .into_iter()
        .filter(|(relative, _)| relative.starts_with("src/commands/"))
        .flat_map(|(relative, text)| literal_sites(&relative, &text, &words))
        .collect();
    found.sort();
    let mut expected: Vec<LiteralSite> = TAILOR_NAMING_DEBT
        .iter()
        .map(|(file, function, literal, count)| {
            (
                file.to_string(),
                function.to_string(),
                literal.to_string(),
                *count,
            )
        })
        .collect();
    expected.sort();
    assert_eq!(
        found, expected,
        "a command names a tailor by string ({words:?}); ask the tailor through a \
         `Tailor` or `RegistryTool` method instead (or, when a row's issue lands, \
         delete the row)"
    );
}

/// Every `/usr/bin/tar` argv lives in `kernel::archive`: extraction runs
/// only through the validated extractor (or the single-member read), and
/// packing (git sources) through its deterministic packer, so the user's
/// `TAR_OPTIONS` cannot reshape what lands in an object. `#[cfg(test)]`
/// items are dropped by `production_tokens`, which exempts test-only
/// extractors and fixture builders; `src/kernel/testutil.rs` is named
/// below because it is test-only by the `cfg(test)` gate on its `mod`
/// declaration in `kernel/mod.rs`, which a per-file scan cannot see.
#[test]
fn tar_runs_only_in_kernel_archive() {
    const OWNER: &str = "src/kernel/archive.rs";
    const TEST_ONLY_BY_MOD_GATE: &[&str] = &["src/kernel/testutil.rs"];
    let mut sites = Vec::new();
    for (relative, text) in all_sources() {
        if !relative.starts_with("src/")
            || relative == OWNER
            || TEST_ONLY_BY_MOD_GATE.contains(&relative.as_str())
        {
            continue;
        }
        for owner in tar_sites(&text) {
            sites.push(format!("{relative}:{owner}"));
        }
    }
    // Positive control: the scan sees the owner's own invocation, so a
    // refactor that moves tar out of a string literal fails loudly here
    // instead of passing silently.
    let root = repo();
    let owner_text = fs::read_to_string(root.join(OWNER)).unwrap();
    assert!(
        production_tokens(&owner_text)
            .iter()
            .any(|(token, _)| matches!(token, Token::Str(literal) if literal == "/usr/bin/tar")),
        "the tar scan no longer sees {OWNER}'s own invocation; it is passing vacuously"
    );
    assert!(
        sites.is_empty(),
        "tar invoked outside kernel::archive (route it through \
         archive::extract_validated_with_activity, archive::read_member, or \
         archive::pack_ustar_with_activity):\n  {}",
        sites.join("\n  ")
    );
}

/// A string literal that names a tar binary: any absolute path ending in
/// `tar`, `bsdtar`, `gtar` or `gnutar`, or one of the last three bare. A bare
/// `"tar"` is not matched here: it is also a file extension
/// (`with_extension`). The scan catches it as a program instead, when it is
/// the argument of `Command::new` (the `program` check in [`tar_sites`]).
fn names_a_tar(literal: &str) -> bool {
    const TARS: [&str; 4] = ["tar", "bsdtar", "gtar", "gnutar"];
    let base = literal.rsplit('/').next().unwrap_or(literal);
    (literal.starts_with('/') && TARS.contains(&base)) || TARS[1..].contains(&literal)
}

/// The owners of every production site in `text` that names tar: a literal
/// [`names_a_tar`] accepts, or a bare `"tar"` given to `Command::new` (any
/// path to `Command`, such as `std::process::Command::new`, ends the same
/// way). A bare `"tar"` anywhere else is a file extension and passes.
fn tar_sites(text: &str) -> Vec<String> {
    let tokens = production_tokens(text);
    let program = |index: usize| {
        let before: Vec<&Token> = tokens[..index]
            .iter()
            .rev()
            .take(5)
            .map(|(token, _)| token)
            .collect();
        matches!(
            before.as_slice(),
            [Token::Punct('('), Token::Ident(new), Token::Punct(':'), Token::Punct(':'), Token::Ident(command)]
                if new == "new" && command == "Command"
        )
    };
    tokens
        .iter()
        .enumerate()
        .filter(|(index, (token, _))| match token {
            Token::Str(literal) => names_a_tar(literal) || (literal == "tar" && program(*index)),
            _ => false,
        })
        .map(|(_, (_, owner))| owner.clone())
        .collect()
}

#[test]
fn a_bare_tar_is_caught_as_a_program_and_not_as_an_extension() {
    assert_eq!(
        tar_sites(
            "fn a() { Command::new(\"tar\").arg(\"-x\"); }\n\
             fn b() { std::process::Command::new(\"tar\"); }\n\
             fn c() { Command::new( \"tar\" ); }\n\
             fn d() { path.with_extension(\"tar\"); }\n\
             fn e() { Command::new(\"gzip\").arg(\"tar\"); }\n\
             fn f() { Command::new(\"/usr/bin/tar\"); }"
        ),
        ["a", "b", "c", "f"]
    );
}

#[test]
fn tar_names_are_recognised_in_every_spelling() {
    for literal in [
        "/usr/bin/tar",
        "/bin/tar",
        "/opt/homebrew/bin/gtar",
        "bsdtar",
        "gnutar",
    ] {
        assert!(names_a_tar(literal), "{literal}");
    }
    for literal in [
        "tar",
        "foo.tar",
        "/usr/bin/star",
        "contents.tar.gz",
        "/usr/bin/gzip",
    ] {
        assert!(!names_a_tar(literal), "{literal}");
    }
}

/// The literal scan reads string contents through every spelling and skips
/// comments, char literals, prose and test-only items.
#[test]
fn the_literal_scan_sees_every_spelling() {
    let words = vec!["node".to_string(), "py".to_string()];
    let text = "fn plain() { f(\"node\"); f(\"node\"); }\n\
        fn raw() { f(r#\"node\"#); f(r\"py\"); }\n\
        fn byte() { f(b\"py\"); }\n\
        fn escaped() { f(\"say \\\"node\\\"\"); f(\"node:\"); }\n\
        fn comment() { // \"node\"\n /* \"py\" */ f('n'); }\n\
        fn path() { f(\".tog/closures/node.json\"); f(\"node.json\"); \
            f(\"node_modules/.bin\"); f(\"run node.js x\"); }\n\
        #[cfg(test)]\nfn test_only() { f(\"node\"); }";
    let site = |function: &str, literal: &str, count: usize| {
        (
            "f.rs".to_string(),
            function.to_string(),
            literal.to_string(),
            count,
        )
    };
    assert_eq!(
        literal_sites("f.rs", text, &words),
        [
            site("plain", "node", 2),
            site("raw", "node", 1),
            site("raw", "py", 1),
            site("byte", "py", 1),
            site("path", ".tog/closures/node.json", 1),
            site("path", "node.json", 1),
        ]
    );
}

/// The files that may name the HTTP client: `kernel::fetch` and its pinned
/// resolver. Everything else fetches through them, so https-only, the
/// redirect and size caps and the user agent hold at every call site.
const HTTP_CLIENT_FILES: &[&str] = &["src/kernel/fetch.rs", "src/kernel/fetch/pinned.rs"];

/// The production lines of `text` that name the `ureq` crate.
fn http_client_sites(text: &str) -> Vec<String> {
    production_tokens(text)
        .into_iter()
        .filter(|(token, _)| is_ident(Some(token), "ureq"))
        .map(|(_, function)| function)
        .collect()
}

#[test]
fn http_goes_through_kernel_fetch() {
    let mut violations = Vec::new();
    for (relative, text) in all_sources() {
        if !relative.starts_with("src/") || HTTP_CLIENT_FILES.contains(&relative.as_str()) {
            continue;
        }
        for function in http_client_sites(&text) {
            violations.push(format!("{relative}: in fn {function}"));
        }
    }
    assert!(
        violations.is_empty(),
        "ureq named outside kernel::fetch (use fetch_text, fetch_text_or_missing, \
         download_file or download_unpinned):\n  {}",
        violations.join("\n  ")
    );
}

#[test]
fn the_http_client_scan_sees_every_spelling() {
    let caught = [
        "fn a() { ureq::get(u).call(); }",
        "use ureq::Agent;\nfn a() {}",
        "fn a() { let x = ureq\n    ::AgentBuilder::new(); }",
        "fn a() -> Option<ureq::RequestUrl> { None }",
    ];
    for text in caught {
        assert!(!http_client_sites(text).is_empty(), "missed: {text}");
    }
    let ignored = [
        "// ureq::get in a comment\nfn a() {}",
        "fn a() { let s = \"ureq::get\"; }",
        "#[cfg(test)]\nmod tests { fn t() { ureq::get(u); } }",
    ];
    for text in ignored {
        assert!(http_client_sites(text).is_empty(), "flagged: {text}");
    }
}

/// Whether `relative` may name `kernel::archive`: the kernel itself, a
/// tailor's `unpack.rs`, and `tog self-update`. heavy.yml's `gate` watches
/// exactly these, so a change to how anything extracts runs the heavy
/// suite against real archives (#325).
fn may_name_archive(relative: &str) -> bool {
    if relative.starts_with("src/kernel/") || relative == "src/commands/selfupdate.rs" {
        return true;
    }
    relative
        .strip_prefix("src/tailors/")
        .and_then(|rest| rest.strip_suffix("/unpack.rs"))
        .is_some_and(|tailor| !tailor.is_empty() && !tailor.contains('/'))
}

/// The production paths of `text` (the source of `relative`) into
/// `kernel::archive`.
fn archive_sites(relative: &str, text: &str) -> Vec<String> {
    let module = module_path(Path::new(relative.trim_start_matches("src/")));
    crate_paths(non_test(text), &module)
        .into_iter()
        .filter(|path| path.len() >= 2 && path[0] == "kernel" && path[1] == "archive")
        .map(|path| path.join("::"))
        .collect()
}

#[test]
fn archive_calls_live_where_the_heavy_gate_looks() {
    let mut violations = Vec::new();
    for (relative, text) in all_sources() {
        if !relative.starts_with("src/") || may_name_archive(&relative) {
            continue;
        }
        for path in archive_sites(&relative, &text) {
            violations.push(format!("{relative}: crate::{path}"));
        }
    }
    assert!(
        violations.is_empty(),
        "kernel::archive named outside src/kernel/, src/tailors/<tailor>/unpack.rs \
         and src/commands/selfupdate.rs; move the call into the tailor's unpack.rs \
         (heavy.yml watches those files):\n  {}",
        violations.join("\n  ")
    );
}

#[test]
fn the_archive_scan_sees_every_spelling() {
    let caught = [
        "fn a() { crate::kernel::archive::list(p, c); }",
        "use crate::kernel::archive::{self, Compression};",
        "use crate::kernel::{archive, store};",
        "use super::super::kernel::archive::Entry;",
    ];
    for text in caught {
        assert!(
            !archive_sites("src/tailors/go/mod.rs", text).is_empty(),
            "{text}"
        );
    }
    let missed = [
        "fn a() { crate::kernel::fetch::download(u); }",
        "// see archive::list",
        "#[cfg(test)]\nmod tests { use crate::kernel::archive::list; }",
    ];
    for text in missed {
        assert!(
            archive_sites("src/tailors/go/mod.rs", text).is_empty(),
            "{text}"
        );
    }
    assert!(may_name_archive("src/tailors/go/unpack.rs"));
    assert!(may_name_archive("src/kernel/provider/rust.rs"));
    assert!(!may_name_archive("src/tailors/go/mod.rs"));
    assert!(!may_name_archive("src/tailors/go/x/unpack.rs"));
    assert!(!may_name_archive("src/commands/sync.rs"));
}

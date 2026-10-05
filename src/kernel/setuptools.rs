//! Static readers for setuptools metadata (`setup.cfg`, a literal
//! `python_requires` in `setup.py`). Shared by toolchain input discovery,
//! which picks the first Python a project locks, and the Python tailor's
//! manifest discovery and interpreter checks, so both read one file one way.
//! Nothing here runs `setup.py`.

use std::collections::BTreeMap;

/// The dependency-bearing subset of setuptools' setup.cfg metadata.
///
/// This is intentionally parsed here, next to the interpreter constraint
/// extractor, so manifest discovery and Python selection share ConfigParser's
/// continuation rules.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SetupCfgMetadata {
    pub install_requires: Vec<String>,
    pub install_requires_found: bool,
    pub python_requires: Option<String>,
    pub extras_require: BTreeMap<String, Vec<String>>,
    pub packages_find: Option<SetupCfgPackagesFind>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SetupCfgPackagesFind {
    pub where_: Vec<String>,
    pub include: Vec<String>,
    pub exclude: Vec<String>,
}

/// Parse the setup.cfg sections used by manifest discovery.
///
/// ConfigParser treats a physical line as a continuation only when it is
/// indented more deeply than the option key. In particular, an indented key
/// is still a key, not a continuation of the previous option.
pub fn parse_setup_cfg(text: &str) -> SetupCfgMetadata {
    let mut section = String::new();
    let mut current_key: Option<String> = None;
    let mut current_values = Vec::new();
    let mut option_indent: Option<usize> = None;
    let mut metadata = SetupCfgMetadata::default();

    let finish =
        |section: &str, key: Option<String>, values: &[String], metadata: &mut SetupCfgMetadata| {
            let Some(key) = key else {
                return;
            };
            if section.eq_ignore_ascii_case("options") {
                match key.as_str() {
                    "install_requires" => {
                        metadata.install_requires_found = true;
                        metadata.install_requires.extend(
                            values
                                .iter()
                                .map(String::as_str)
                                .filter(|value| !value.trim().is_empty())
                                .map(str::to_string),
                        );
                    }
                    "python_requires" => {
                        let value = values
                            .iter()
                            .map(String::as_str)
                            .filter(|value| !value.trim().is_empty())
                            .collect::<Vec<_>>()
                            .join(" ");
                        if !value.is_empty() {
                            metadata.python_requires = Some(value);
                        }
                    }
                    _ => {}
                }
            } else if section.eq_ignore_ascii_case("options.extras_require") {
                for value in values.iter().filter(|value| !value.trim().is_empty()) {
                    metadata
                        .extras_require
                        .entry(key.clone())
                        .or_default()
                        .push(value.trim().to_string());
                }
            } else if section.eq_ignore_ascii_case("options.packages.find") {
                let packages = metadata.packages_find.get_or_insert_with(Default::default);
                for value in values.iter().filter(|value| !value.trim().is_empty()) {
                    let values = value
                        .split_whitespace()
                        .map(str::to_string)
                        .collect::<Vec<_>>();
                    match key.as_str() {
                        "where" => packages.where_.extend(values),
                        "include" => packages.include.extend(values),
                        "exclude" => packages.exclude.extend(values),
                        _ => {}
                    }
                }
            }
        };

    for raw in text.lines() {
        // ConfigParser ignores full-line comments before it applies the
        // continuation indentation rule. An unindented `; comment` therefore
        // cannot terminate a multi-line install_requires value.
        let raw_trimmed = raw.trim_start();
        if raw_trimmed.starts_with('#') || raw_trimmed.starts_with(';') {
            continue;
        }
        let line = strip_setup_cfg_comment(raw);
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        if option_indent.is_some_and(|active| indent > active) {
            current_values.push(trimmed.to_string());
            continue;
        }

        finish(&section, current_key.take(), &current_values, &mut metadata);
        current_values.clear();
        option_indent = None;

        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            section = trimmed[1..trimmed.len() - 1].trim().to_ascii_lowercase();
            continue;
        }

        option_indent = Some(indent);
        let Some(separator) = trimmed.find(['=', ':']) else {
            continue;
        };
        current_key = Some(trimmed[..separator].trim().to_ascii_lowercase());
        let value = trimmed[separator + 1..].trim();
        if !value.is_empty() {
            current_values.push(value.to_string());
        }
    }
    finish(&section, current_key, &current_values, &mut metadata);
    metadata
}

fn strip_setup_cfg_comment(line: &str) -> &str {
    line.char_indices()
        .find(|(index, character)| {
            *character == '#' && (*index == 0 || line.as_bytes()[*index - 1].is_ascii_whitespace())
        })
        .map(|(index, _)| &line[..index])
        .unwrap_or(line)
}

/// A literal `python_requires="..."` in `setup.py`, found without running
/// the file: the first assignment whose whole value is one plain string.
///
/// Comments and the insides of other strings are skipped, so a
/// commented-out line or example code in a docstring is not an assignment,
/// and neither is a longer name (`extra_python_requires`) or an attribute
/// (`args.python_requires`). A value that is computed (two strings joined,
/// a format, a comparison, an escape) is not seen at all: half of it would
/// be the wrong constraint. The value is whole when the argument ends
/// after it (`,` or `)` inside brackets) or the statement does (outside).
pub fn extract_setup_py_python_requires(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut pos = 0;
    // How many brackets are open: inside them a line end is only spacing.
    let mut depth = 0usize;
    // The last byte that was not spacing or a comment, for `x . name`.
    let mut before = None;
    while let Some(&byte) = bytes.get(pos) {
        if byte == b'#' {
            pos = line_end(bytes, pos);
        } else if byte == b'\'' || byte == b'"' {
            // A string that never closes: not Python a value can be read from.
            pos = string_end(bytes, pos, is_fstring(bytes, pos))?;
            before = Some(byte);
        } else if is_name_byte(byte) {
            let start = pos;
            while bytes.get(pos).copied().is_some_and(is_name_byte) {
                pos += 1;
            }
            let attribute = before == Some(b'.');
            before = Some(byte);
            if &text[start..pos] != "python_requires" || attribute {
                continue;
            }
            let grouped = depth > 0;
            let equals = skip_spacing(bytes, pos, grouped);
            if bytes.get(equals) != Some(&b'=') || bytes.get(equals + 1) == Some(&b'=') {
                continue;
            }
            let value = skip_spacing(bytes, equals + 1, grouped);
            if let Some(value) = whole_literal(text, value, grouped) {
                return Some(value);
            }
        } else {
            match byte {
                b'(' | b'[' | b'{' => depth += 1,
                b')' | b']' | b'}' => depth = depth.saturating_sub(1),
                _ => {}
            }
            if !byte.is_ascii_whitespace() {
                before = Some(byte);
            }
            pos += 1;
        }
    }
    None
}

fn is_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || !byte.is_ascii()
}

/// Past spaces and tabs. When `lines` (inside brackets), past line ends
/// and comments too.
fn skip_spacing(bytes: &[u8], mut pos: usize, lines: bool) -> usize {
    loop {
        match bytes.get(pos) {
            Some(b' ' | b'\t') => pos += 1,
            Some(b'\n' | b'\r') if lines => pos += 1,
            Some(b'#') if lines => pos = line_end(bytes, pos),
            _ => return pos,
        }
    }
}

/// The index of the newline ending the line `pos` is on, or the end.
fn line_end(bytes: &[u8], pos: usize) -> usize {
    bytes[pos..]
        .iter()
        .position(|byte| *byte == b'\n')
        .map_or(bytes.len(), |offset| pos + offset)
}

/// Whether the string whose opening quote is at `pos` has an f-string
/// prefix (`f"`, `rf"`, `Fr"`).
fn is_fstring(bytes: &[u8], pos: usize) -> bool {
    let start = bytes[..pos]
        .iter()
        .rposition(|byte| !is_name_byte(*byte))
        .map_or(0, |index| index + 1);
    let prefix = &bytes[start..pos];
    prefix.len() <= 2
        && prefix.iter().any(|byte| matches!(byte, b'f' | b'F'))
        && prefix
            .iter()
            .all(|byte| matches!(byte, b'f' | b'F' | b'r' | b'R'))
}

/// The string literal whose opening quote is at `pos`: where its content
/// starts and ends, and the index after its closing quote. `None` when it
/// is never closed.
fn string_span(bytes: &[u8], pos: usize, fstring: bool) -> Option<(usize, usize, usize)> {
    let quote = bytes[pos];
    let triple = bytes.get(pos + 1) == Some(&quote) && bytes.get(pos + 2) == Some(&quote);
    let width = if triple { 3 } else { 1 };
    let start = pos + width;
    let mut at = start;
    while let Some(&byte) = bytes.get(at) {
        if byte == b'\\' {
            at += 2;
        } else if byte == b'\n' && !triple {
            return None;
        } else if byte == quote && (!triple || bytes[at..].starts_with(&[quote; 3])) {
            return Some((start, at, at + width));
        } else if fstring && byte == b'{' && bytes.get(at + 1) != Some(&b'{') {
            at = replacement_field_end(bytes, at + 1)?;
        } else if fstring && byte == b'{' {
            at += 2;
        } else {
            at += 1;
        }
    }
    None
}

fn string_end(bytes: &[u8], pos: usize, fstring: bool) -> Option<usize> {
    string_span(bytes, pos, fstring).map(|(_, _, after)| after)
}

/// The index after the `}` closing an f-string replacement field that
/// opened just before `pos`. The field holds an expression, which may
/// itself contain strings, with the same quote as the f-string since
/// Python 3.12: those are skipped whole, so their quotes close nothing.
fn replacement_field_end(bytes: &[u8], mut pos: usize) -> Option<usize> {
    let mut depth = 1usize;
    while let Some(&byte) = bytes.get(pos) {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(pos + 1);
                }
            }
            b'\'' | b'"' => {
                pos = string_end(bytes, pos, is_fstring(bytes, pos))?;
                continue;
            }
            _ => {}
        }
        pos += 1;
    }
    None
}

/// The string at `pos` when it is the assignment's whole value: one plain
/// literal with no prefix and no escape, after which the argument ends
/// (`grouped`: the assignment is inside brackets) or the statement does.
fn whole_literal(text: &str, pos: usize, grouped: bool) -> Option<String> {
    let bytes = text.as_bytes();
    if !matches!(bytes.get(pos), Some(b'\'' | b'"')) {
        return None;
    }
    let (start, end, after) = string_span(bytes, pos, false)?;
    let value = &text[start..end];
    if value.contains('\\') {
        return None;
    }
    let mut next = skip_spacing(bytes, after, grouped);
    if bytes.get(next) == Some(&b'#') {
        next = line_end(bytes, next);
    }
    let ends = match bytes.get(next) {
        Some(b',' | b')') => grouped,
        None | Some(b'\n' | b'\r' | b';') => !grouped,
        Some(_) => false,
    };
    ends.then(|| value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn found(text: &str) -> Option<String> {
        extract_setup_py_python_requires(text)
    }

    #[test]
    fn setup_py_python_requires_is_a_whole_plain_literal() {
        assert_eq!(
            found("setup(name='x', python_requires = \">=3.9\")").as_deref(),
            Some(">=3.9")
        );
        assert_eq!(
            found("setup(\n    python_requires='>=3.9,<3.13',  # supported\n)\n").as_deref(),
            Some(">=3.9,<3.13")
        );
        assert_eq!(
            found("setup(\n    python_requires=\">=3.9\"\n)\n").as_deref(),
            Some(">=3.9")
        );
        assert_eq!(
            found("python_requires = \">=3.10\"\nsetup(name=\"x\")\n").as_deref(),
            Some(">=3.10")
        );
        // The value may start on the line after the `=` inside the call.
        assert_eq!(
            found("setup(\n    python_requires=\n        \">=3.12\",\n)\n").as_deref(),
            Some(">=3.12")
        );
        assert_eq!(
            found("setup(\n    python_requires=\">=3.12\"  # floor\n    # more\n)\n").as_deref(),
            Some(">=3.12")
        );
        assert_eq!(
            found("kw = {\"a\": [1, 2]}\nsetup(python_requires='>=3.7', **kw)\n").as_deref(),
            Some(">=3.7")
        );
        assert_eq!(
            found("setup(python_requires=\"\"\">=3.11\"\"\")").as_deref(),
            Some(">=3.11")
        );
    }

    /// A commented-out assignment, example code inside a string, a longer
    /// name, an attribute and a comparison are not the assignment.
    #[test]
    fn setup_py_scan_skips_what_is_not_the_assignment() {
        assert_eq!(
            found("# python_requires=\"<3.12\"\nsetup(python_requires=\">=3.12\")\n").as_deref(),
            Some(">=3.12")
        );
        assert_eq!(
            found("\"\"\"Use python_requires=\"<3\" here.\"\"\"\nsetup(python_requires='>=3.8')\n")
                .as_deref(),
            Some(">=3.8")
        );
        assert_eq!(
            found("note = 'python_requires=\"<3\"'\nsetup(python_requires='>=3.8')\n").as_deref(),
            Some(">=3.8")
        );
        assert_eq!(found("setup(extra_python_requires=\">=3.9\")"), None);
        assert_eq!(found("setup(python_requires_extra=\">=3.9\")"), None);
        assert_eq!(found("args.python_requires = \">=3.9\"\n"), None);
        assert_eq!(
            found("args. python_requires = \"<3.10\"\nsetup(python_requires=\">=3.12\")\n")
                .as_deref(),
            Some(">=3.12")
        );
        // A string nested in an f-string's replacement field (Python 3.12)
        // does not end the f-string.
        assert_eq!(
            found(
                "note = f\"{ \"python_requires='<3.10',\" }\"\nsetup(python_requires=\">=3.12\")\n"
            )
            .as_deref(),
            Some(">=3.12")
        );
        assert_eq!(
            found("note = f\"{{python_requires='<3.10',}}\"\nsetup(python_requires=\">=3.12\")\n")
                .as_deref(),
            Some(">=3.12")
        );

        assert_eq!(found("if python_requires == \">=3.9\":\n    pass\n"), None);
    }

    /// A value that is computed is not read, not even its first half.
    #[test]
    fn setup_py_scan_does_not_read_a_computed_value() {
        assert_eq!(found("setup(python_requires=\">=3.9\" + \",<3.12\")"), None);
        assert_eq!(found("setup(python_requires=\">=3.9\" \",<3.12\")"), None);
        assert_eq!(
            found("setup(\n    python_requires=\">=3.9\"\n    \",<3.12\",\n)\n"),
            None
        );
        assert_eq!(found("setup(python_requires=\">=%s\" % MIN)"), None);
        assert_eq!(found("setup(python_requires=\">={}\".format(MIN))"), None);
        assert_eq!(found("setup(python_requires=f\">={MIN}\")"), None);
        assert_eq!(found("setup(python_requires=MIN)"), None);
        assert_eq!(found("setup(python_requires=\">=3.9\\n\")"), None);
        assert_eq!(found("setup(python_requires=\">=3.9)\n"), None);
        // An operator on the next line still extends the expression.
        assert_eq!(
            found("setup(\n    python_requires=\">=3.9\"\n        == x and \">=3.12\" or \">=3.13\",\n)\n"),
            None
        );
        assert_eq!(
            found("setup(python_requires=\">=3.9\" if x else \">=3.8\")"),
            None
        );
        assert_eq!(
            found("python_requires = \">=3.9\" \\\n    \",<3.12\"\n"),
            None
        );
        // A later plain assignment is still found after a computed one.
        assert_eq!(
            found("x = dict(python_requires=MIN)\nsetup(python_requires='>=3.9')\n").as_deref(),
            Some(">=3.9")
        );
    }
}

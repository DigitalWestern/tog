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

pub fn extract_setup_py_python_requires(text: &str) -> Option<String> {
    let key = "python_requires";
    let mut search_from = 0;
    while let Some(found) = text[search_from..].find(key) {
        let start = search_from + found + key.len();
        let mut pos = start;
        while text
            .as_bytes()
            .get(pos)
            .is_some_and(u8::is_ascii_whitespace)
        {
            pos += 1;
        }
        if text.as_bytes().get(pos) != Some(&b'=') {
            search_from = start;
            continue;
        }
        pos += 1;
        while text
            .as_bytes()
            .get(pos)
            .is_some_and(u8::is_ascii_whitespace)
        {
            pos += 1;
        }
        let &quote = text.as_bytes().get(pos)?;
        if quote != b'\'' && quote != b'"' {
            search_from = pos;
            continue;
        }
        pos += 1;
        let value_start = pos;
        while let Some(&byte) = text.as_bytes().get(pos) {
            if byte == quote {
                return Some(text[value_start..pos].to_string());
            }
            pos += 1;
        }
        return None;
    }
    None
}

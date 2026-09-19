//! setup.py projects (python tailor): the provably-trivial check, the
//! setup tree hash, and the cached setup-derived inputs.

use super::*;

pub(super) fn replace_setup_requires_python(inputs: &mut PythonInputs, value: Option<String>) {
    inputs
        .constraints
        .retain(|constraint| constraint.source != "setup.py PKG-INFO");
    if let Some(value) = value {
        inputs
            .constraints
            .push(ConstraintSource::new(value, "setup.py PKG-INFO"));
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub(super) struct SetupCache {
    pub(super) tree_hash: String,
    pub(super) requirements: Vec<String>,
    pub(super) requires_python: Option<String>,
    #[serde(default)]
    pub(super) python_version: String,
    #[serde(default)]
    pub(super) platform: String,
    #[serde(default)]
    pub(super) build_toolchain: String,
}

pub(super) fn setup_cache_matches(
    cache: &SetupCache,
    tree_hash: &str,
    platform: Platform,
    python_version: &str,
    build_toolchain: &str,
) -> bool {
    cache.tree_hash == tree_hash
        && cache.python_version == python_version
        && cache.platform == platform.triple()
        && cache.build_toolchain == build_toolchain
}

#[cfg(test)]
pub(super) fn is_trivial_setup_py(text: &str) -> bool {
    let mut code = String::new();
    for line in text.lines() {
        let line = strip_inline_comment(line).trim();
        if !line.is_empty() {
            code.push_str(line);
            code.push('\n');
        }
    }
    let Some(call_start) = code
        .find("setuptools.setup(")
        .or_else(|| code.find("setup("))
    else {
        return false;
    };
    let prefix = code[..call_start].trim();
    let import_only = prefix
        .lines()
        .all(|line| line.starts_with("from setuptools") || line.starts_with("import setuptools"));
    if !import_only || code[call_start..].matches("setup(").count() != 1 {
        return false;
    }
    let mut depth = 0i32;
    let mut end = None;
    for (offset, character) in code[call_start..].char_indices() {
        match character {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    end = Some(call_start + offset + character.len_utf8());
                    break;
                }
                if depth < 0 {
                    return false;
                }
            }
            _ => {}
        }
    }
    end.is_some_and(|end| {
        if !code[end..].trim().is_empty() {
            return false;
        }
        let call = &code[call_start..end];
        ![
            "install_requires",
            "extras_require",
            "setup_requires",
            "tests_require",
        ]
        .iter()
        .any(|argument| call.contains(argument))
    })
}

pub(super) fn setup_py_has_setup_call(text: &str) -> bool {
    let mut setup_names = BTreeSet::from(["setup".to_string()]);
    let mut setuptools_names = BTreeSet::from(["setuptools".to_string()]);
    for raw in text.lines() {
        let line = strip_inline_comment(raw).trim();
        for statement in line.split(';').map(str::trim) {
            if let Some(imports) = statement.strip_prefix("from setuptools import") {
                for item in imports.split(',') {
                    let words = item.split_whitespace().collect::<Vec<_>>();
                    if words.first() == Some(&"setup") {
                        setup_names.insert(
                            words
                                .iter()
                                .position(|word| *word == "as")
                                .and_then(|position| words.get(position + 1))
                                .copied()
                                .unwrap_or("setup")
                                .to_string(),
                        );
                    }
                }
            }
            if let Some(imports) = statement.strip_prefix("import ") {
                for item in imports.split(',') {
                    let words = item.split_whitespace().collect::<Vec<_>>();
                    if words.first() == Some(&"setuptools") {
                        setuptools_names.insert(
                            words
                                .iter()
                                .position(|word| *word == "as")
                                .and_then(|position| words.get(position + 1))
                                .copied()
                                .unwrap_or("setuptools")
                                .to_string(),
                        );
                    }
                }
            }
        }
    }
    let code = python_code_without_strings(text);
    setup_names
        .iter()
        .any(|name| python_call_named(&code, name))
        || setuptools_names
            .iter()
            .any(|name| python_call_named(&code, &format!("{name}.setup")))
}

pub(super) fn setup_py_is_provably_trivial(text: &str) -> bool {
    let code = python_code_without_strings(text);
    !setup_py_has_setup_call(text) && !code.contains('(')
}

pub(super) fn python_call_named(code: &str, name: &str) -> bool {
    code.match_indices(name).any(|(start, _)| {
        let before = code[..start].chars().next_back();
        let after = &code[start + name.len()..];
        let valid_before = before.is_none_or(|character| {
            !character.is_ascii_alphanumeric() && character != '_' && character != '.'
        });
        let mut after = after.chars();
        let valid_after = after
            .by_ref()
            .find(|character| !character.is_ascii_whitespace())
            == Some('(');
        valid_before && valid_after
    })
}

pub(super) fn python_code_without_strings(text: &str) -> String {
    let mut output = String::with_capacity(text.len());
    let mut quote = None;
    let mut escaped = false;
    let mut comment = false;
    for character in text.chars() {
        if comment {
            if character == '\n' {
                comment = false;
                output.push(character);
            } else {
                output.push(' ');
            }
            continue;
        }
        if let Some(current) = quote {
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == current {
                quote = None;
            }
            output.push(if character == '\n' { '\n' } else { ' ' });
            continue;
        }
        match character {
            '#' => {
                comment = true;
                output.push(' ');
            }
            '\'' | '"' => {
                quote = Some(character);
                output.push(' ');
            }
            _ => output.push(character),
        }
    }
    output
}

pub(super) fn parse_requires_python_metadata(text: &str) -> Option<String> {
    text.lines().find_map(|line| {
        line.strip_prefix("Requires-Python:")
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(str::to_string)
    })
}

pub(super) fn setup_tree_hash(dir: &Path) -> io::Result<String> {
    let mut paths = BTreeSet::new();
    collect_setup_files(dir, &mut paths)?;
    let mut hasher = Sha256::new();
    for path in paths {
        let relative = path.strip_prefix(dir).unwrap_or(&path);
        hasher.update(relative.to_string_lossy().as_bytes());
        hasher.update([0]);
        hasher.update(fs::read(&path).map_err(|e| unreadable(&path, e))?);
        hasher.update([0]);
    }
    Ok(hex::encode(hasher.finalize()))
}

pub(super) fn collect_setup_files(path: &Path, files: &mut BTreeSet<PathBuf>) -> io::Result<()> {
    let mut entries = fs::read_dir(path)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let child = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        if matches!(
            name.as_str(),
            ".git" | ".tog" | "__pycache__" | ".venv" | "node_modules"
        ) || name.ends_with(".egg-info")
            || name == "requirements.lock.txt"
        {
            continue;
        }
        let metadata = fs::symlink_metadata(&child)?;
        if metadata.file_type().is_dir() {
            collect_setup_files(&child, files)?;
        } else {
            files.insert(child);
        }
    }
    Ok(())
}

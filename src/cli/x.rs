//! `tog x`'s grammar: the tool, its registry, its version, and the
//! arguments handed to it.

use super::parse::{non_empty, reject, separate_value};
use super::spec::X_REGISTRIES;
use super::{Command, UsageError};

pub(super) fn parse_x(args: &[String]) -> Result<Option<Command>, UsageError> {
    let mut ecosystem = None;
    let mut from = None;
    let mut clean = false;
    let mut index = 0;
    while let Some(arg) = args.get(index).map(String::as_str) {
        match arg {
            "-h" | "--help" => return Ok(None),
            "--clean" => clean = true,
            _ if x_registry_flag(arg).is_some() => {
                ecosystem = x_registry_flag(arg).map(str::to_string);
            }
            "--from" => {
                let value = separate_value(args, index, arg, Some("x"), "a package name")?;
                validate_x_package(value)?;
                from = Some(value.to_string());
                index += 1;
            }
            _ if arg.starts_with("--from=") => {
                let value = non_empty(&arg["--from=".len()..], "--from", Some("x"))?
                    .to_string_lossy()
                    .into_owned();
                validate_x_package(&value)?;
                from = Some(value);
            }
            "--" => {
                index += 1;
                break;
            }
            _ if arg.starts_with('-') && arg.len() > 1 => return Err(reject("x", arg)),
            _ => break,
        }
        index += 1;
    }
    let Some(tool) = args.get(index) else {
        if clean {
            if from.is_some() {
                return Err(UsageError::new(
                    "x: --clean --from requires a tool name",
                    Some("x"),
                ));
            }
            return Ok(Some(Command::XClean {
                ecosystem,
                from,
                tool: None,
            }));
        }
        return Err(UsageError::new(
            "x: no tool given (e.g. 'tog x ruff check .', 'tog x npm:prettier --write .')",
            Some("x"),
        ));
    };
    let mut tool = tool.clone();
    if let Some((id, rest)) = X_REGISTRIES.iter().find_map(|(id, word)| {
        let rest = tool.strip_prefix(word)?.strip_prefix(':')?;
        Some((*id, rest.to_string()))
    }) {
        ecosystem = Some(id.to_string());
        tool = rest;
    }
    if clean && args.get(index + 1).is_some() {
        return Err(UsageError::new(
            format!("x --clean: unexpected argument '{}'", args[index + 1]),
            Some("x"),
        ));
    }
    if tool.is_empty() {
        return Err(UsageError::new("x: empty tool name", Some("x")));
    }
    if from.is_some() {
        let (bin, _) = split_x_version(&tool);
        validate_x_bin(bin)?;
    } else {
        // Without --from the tool is also the package name, so npm scoped
        // names such as @scope/cli legitimately contain one slash.
        validate_x_text("tool", &tool, true)?;
    }
    validate_x_version_pair(from.as_deref(), &tool)?;
    if clean {
        return Ok(Some(Command::XClean {
            ecosystem,
            from,
            tool: Some(tool),
        }));
    }
    Ok(Some(Command::X {
        ecosystem,
        from,
        tool,
        args: args[index + 1..].to_vec(),
    }))
}

/// The tailor id an `x` registry flag selects: `--<word>` or `--<id>` of an
/// `X_REGISTRIES` row.
fn x_registry_flag(arg: &str) -> Option<&'static str> {
    let name = arg.strip_prefix("--")?;
    X_REGISTRIES
        .iter()
        .find(|(id, word)| name == *id || name == *word)
        .map(|(id, _)| *id)
}

fn split_x_version(value: &str) -> (&str, Option<&str>) {
    match value.rfind('@') {
        Some(0) | None => (value, None),
        Some(index) => (&value[..index], Some(&value[index + 1..])),
    }
}

fn validate_x_version_pair(from: Option<&str>, tool: &str) -> Result<(), UsageError> {
    let (_, tool_version) = split_x_version(tool);
    let from_version = from.and_then(|value| split_x_version(value).1);
    for version in [from_version, tool_version].into_iter().flatten() {
        if version.is_empty()
            || version
                .bytes()
                .any(|byte| matches!(byte, b'\r' | b'\n' | 0))
            || version.chars().any(char::is_whitespace)
            || version.starts_with('-')
        {
            return Err(UsageError::new("x: invalid version", Some("x")));
        }
    }
    if let (Some(from), Some(tool)) = (from_version, tool_version) {
        if from != tool {
            return Err(UsageError::new(
                "x: --from package version conflicts with the tool version; specify only one or use the same version",
                Some("x"),
            ));
        }
    }
    Ok(())
}

fn validate_x_text(label: &str, value: &str, allow_slash: bool) -> Result<(), UsageError> {
    if value.is_empty()
        || value.bytes().any(|byte| matches!(byte, b'\r' | b'\n' | 0))
        || value.chars().any(char::is_whitespace)
        || value.starts_with('-')
        || (!allow_slash && (value.contains('/') || value.contains('\\')))
    {
        return Err(UsageError::new(
            format!("x: invalid {label} '{value}'"),
            Some("x"),
        ));
    }
    Ok(())
}

fn validate_x_package(value: &str) -> Result<(), UsageError> {
    // A scoped npm package contains one slash, but a filesystem path must
    // never be accepted as a package name. Version text is checked by
    // `validate_x_version_pair`; these checks keep argv errors at exit 2.
    validate_x_text("package", value, true)?;
    if value.starts_with('/')
        || value.starts_with("./")
        || value.starts_with("../")
        || value.contains("/../")
        || value.ends_with("/..")
        || value.contains('\\')
    {
        return Err(UsageError::new(
            format!("x: invalid package '{value}'"),
            Some("x"),
        ));
    }
    Ok(())
}

fn validate_x_bin(value: &str) -> Result<(), UsageError> {
    if value.is_empty()
        || value == "."
        || value == ".."
        || !value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ".-_".contains(ch))
    {
        return Err(UsageError::new(
            "x: --from requires a single safe executable name",
            Some("x"),
        ));
    }
    Ok(())
}

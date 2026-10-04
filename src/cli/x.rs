//! `tog x`'s grammar: the tool, its registry, its version, and the
//! arguments handed to it.

use super::parse::{non_empty, reject, separate_value};
use super::spec::X_REGISTRIES;
use super::{Command, UsageError};
// The argument rules live with the command, which re-checks them; the
// parser calls the same functions so a bad spelling exits 2.
use crate::commands::x::{request_version, split_version, validate_from_bin, validate_package};

fn usage(error: std::io::Error) -> UsageError {
    UsageError::new(error.to_string(), Some("x"))
}

/// A `--from` value: a package, perhaps with `@version`.
fn validate_x_package(value: &str) -> Result<(), UsageError> {
    validate_package("package", split_version(value).0).map_err(usage)
}

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
    let (bin, tool_version) = split_version(&tool);
    if from.is_some() {
        validate_from_bin(bin).map_err(usage)?;
    } else {
        // Without --from the tool is also the package name, so npm scoped
        // names such as @scope/cli legitimately contain one slash.
        validate_package("tool", bin).map_err(usage)?;
    }
    let from_version = from.as_deref().and_then(|value| split_version(value).1);
    request_version(tool_version, from_version).map_err(usage)?;
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

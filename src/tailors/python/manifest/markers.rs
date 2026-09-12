//! PEP 508 environment-marker evaluation (python tailor) for lock
//! resolution: which of a package's dependencies apply on this platform.

use super::*;

/// Evaluate the small PEP 508 marker subset emitted by Poetry and uv lock
/// files. Lock variants must be filtered before graph traversal, so retaining
/// the marker text and handing it to an unconstrained resolver is not enough.
pub(super) fn marker_matches(
    expression: &str,
    python_version: &str,
    platform: Platform,
) -> io::Result<bool> {
    marker_matches_for_extra(expression, python_version, platform, None)
}

pub(super) fn marker_matches_for_extra(
    expression: &str,
    python_version: &str,
    platform: Platform,
    extra: Option<&str>,
) -> io::Result<bool> {
    let expression = strip_marker_parens(expression.trim());
    if expression.is_empty() {
        return Ok(true);
    }
    let alternatives = split_marker_keyword(expression, "or");
    if alternatives.len() > 1 {
        return alternatives
            .into_iter()
            .map(|part| marker_matches_for_extra(part, python_version, platform, extra))
            .collect::<io::Result<Vec<_>>>()
            .map(|values| values.into_iter().any(|value| value));
    }
    let conjunction = split_marker_keyword(expression, "and");
    if conjunction.len() > 1 {
        return conjunction
            .into_iter()
            .map(|part| marker_matches_for_extra(part, python_version, platform, extra))
            .collect::<io::Result<Vec<_>>>()
            .map(|values| values.into_iter().all(|value| value));
    }
    if let Some(rest) = expression.strip_prefix("not ") {
        return marker_matches_for_extra(rest, python_version, platform, extra).map(|value| !value);
    }

    let operators = [
        " not in ", " in ", ">=", "<=", "===", "~=", "==", "!=", ">", "<",
    ];
    let (left, operator, right) = operators
        .iter()
        .find_map(|operator| {
            expression.find(operator).map(|index| {
                (
                    expression[..index].trim(),
                    *operator,
                    expression[index + operator.len()..].trim(),
                )
            })
        })
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported environment marker `{expression}`"),
            )
        })?;
    let (left_value, left_is_variable) =
        marker_operand_value(left, python_version, platform, extra).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported environment marker operand `{left}`"),
            )
        })?;
    let (right_value, right_is_variable) =
        marker_operand_value(right, python_version, platform, extra).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported environment marker operand `{right}`"),
            )
        })?;
    // PEP 508 defines membership as a string operation, including when the
    // left operand is python_version.
    if operator == " in " {
        return Ok(right_value.contains(left_value.as_str()));
    }
    if operator == " not in " {
        return Ok(!right_value.contains(left_value.as_str()));
    }
    if (left_is_variable && is_python_marker(left))
        || (right_is_variable && is_python_marker(right))
    {
        return crate::tailors::python::pep440::matches_specifier(
            &format!("{}{}", operator.trim(), right_value),
            &left_value,
        );
    }
    Ok(match operator {
        "==" => left_value == right_value,
        "!=" => left_value != right_value,
        ">=" => left_value.as_str() >= right_value.as_str(),
        "<=" => left_value.as_str() <= right_value.as_str(),
        ">" => left_value.as_str() > right_value.as_str(),
        "<" => left_value.as_str() < right_value.as_str(),
        "===" => left_value == right_value,
        "~=" => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "version marker operator `~=` needs a Python version operand: `{expression}`"
                ),
            ))
        }
        _ => false,
    })
}

pub(super) fn marker_operand_value(
    operand: &str,
    python_version: &str,
    platform: Platform,
    extra: Option<&str>,
) -> Option<(String, bool)> {
    if let Some(value) = marker_value(operand, python_version, platform, extra) {
        return Some((value, true));
    }
    marker_string_value(operand).map(|value| (value, false))
}

pub(super) fn marker_string_value(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    if bytes.len() < 2 || !matches!(bytes[0], b'\'' | b'"') || bytes.last() != Some(&bytes[0]) {
        return None;
    }
    Some(value[1..value.len() - 1].to_string())
}

pub(super) fn is_python_marker(name: &str) -> bool {
    matches!(name, "python_version" | "python_full_version")
}

pub(super) fn marker_value(
    name: &str,
    python_version: &str,
    platform: Platform,
    extra: Option<&str>,
) -> Option<String> {
    let python_full_version = python_version.to_string();
    let python_version = python_version
        .split('.')
        .take(2)
        .collect::<Vec<_>>()
        .join(".");
    Some(match name {
        "python_version" => python_version,
        "python_full_version" => python_full_version,
        "sys_platform" => if matches!(platform, Platform::Aarch64AppleDarwin) {
            "darwin"
        } else {
            "linux"
        }
        .to_string(),
        "os_name" => "posix".to_string(),
        "platform_system" => if matches!(platform, Platform::Aarch64AppleDarwin) {
            "Darwin"
        } else {
            "Linux"
        }
        .to_string(),
        "platform_machine" => if matches!(platform, Platform::Aarch64AppleDarwin) {
            "arm64"
        } else {
            "x86_64"
        }
        .to_string(),
        "implementation_name" => "cpython".to_string(),
        "platform_python_implementation" => "CPython".to_string(),
        "extra" => extra.unwrap_or_default().to_string(),
        _ => return None,
    })
}

pub(super) fn strip_marker_parens(mut expression: &str) -> &str {
    loop {
        let bytes = expression.as_bytes();
        if bytes.first() != Some(&b'(') || bytes.last() != Some(&b')') {
            return expression;
        }
        let mut depth = 0;
        let mut quote = None;
        let mut closes_early = false;
        for (index, byte) in bytes.iter().copied().enumerate() {
            if let Some(current) = quote {
                if byte == current && (index == 0 || bytes[index - 1] != b'\\') {
                    quote = None;
                }
                continue;
            }
            if byte == b'\'' || byte == b'"' {
                quote = Some(byte);
            } else if byte == b'(' {
                depth += 1;
            } else if byte == b')' {
                depth -= 1;
                if depth == 0 && index != bytes.len() - 1 {
                    closes_early = true;
                    break;
                }
            }
        }
        if closes_early || depth != 0 {
            return expression;
        }
        expression = expression[1..expression.len() - 1].trim();
    }
}

pub(super) fn split_marker_keyword<'a>(expression: &'a str, keyword: &str) -> Vec<&'a str> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut depth = 0i32;
    let mut quote = None;
    let bytes = expression.as_bytes();
    for index in 0..bytes.len() {
        let byte = bytes[index];
        if let Some(current) = quote {
            if byte == current && (index == 0 || bytes[index - 1] != b'\\') {
                quote = None;
            }
            continue;
        }
        if byte == b'\'' || byte == b'"' {
            quote = Some(byte);
            continue;
        }
        match byte {
            b'(' => depth += 1,
            b')' => depth -= 1,
            _ => {}
        }
        let end = index + keyword.len();
        let boundary_before = index == 0 || bytes[index - 1].is_ascii_whitespace();
        let boundary_after = end >= bytes.len() || bytes[end].is_ascii_whitespace();
        if depth == 0
            && boundary_before
            && boundary_after
            && expression[index..].starts_with(keyword)
        {
            parts.push(expression[start..index].trim());
            start = end;
        }
    }
    if parts.is_empty() {
        vec![expression]
    } else {
        parts.push(expression[start..].trim());
        parts
    }
}

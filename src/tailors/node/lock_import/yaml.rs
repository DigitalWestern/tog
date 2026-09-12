//! The minimal YAML reader (node tailor) that pnpm-lock.yaml needs: block
//! maps and lists, inline flow values, quoted scalars. Nothing else.

use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum YamlValue {
    Scalar(String),
    Map(BTreeMap<String, YamlValue>),
    Seq(Vec<YamlValue>),
}

#[derive(Debug, Clone)]
pub(super) struct YamlLine {
    pub(super) number: usize,
    pub(super) indent: usize,
    pub(super) text: String,
}

pub(super) fn yaml_unquote(value: &str) -> String {
    let value = value.trim();
    if value.len() >= 2 && value.starts_with('"') && value.ends_with('"') {
        serde_json::from_str(value).unwrap_or_else(|_| value[1..value.len() - 1].to_string())
    } else if value.len() >= 2 && value.starts_with('\'') && value.ends_with('\'') {
        value[1..value.len() - 1].replace("''", "'")
    } else {
        value.to_string()
    }
}

pub(super) fn split_top_level(value: &str, separator: char) -> Vec<String> {
    let mut result = Vec::new();
    let mut start = 0;
    let mut depth = 0i32;
    let mut quote = None;
    let chars: Vec<char> = value.chars().collect();
    for (i, ch) in chars.iter().enumerate() {
        match quote {
            Some('\'') if *ch == '\'' => {
                if chars.get(i + 1) == Some(&'\'') {
                    continue;
                }
                quote = None;
            }
            Some('"') if *ch == '"' => quote = None,
            Some(_) => {}
            None => match ch {
                '\'' | '"' => quote = Some(*ch),
                '[' | '{' | '(' => depth += 1,
                ']' | '}' | ')' => depth -= 1,
                c if *c == separator && depth == 0 => {
                    result.push(chars[start..i].iter().collect::<String>());
                    start = i + 1;
                }
                _ => {}
            },
        }
    }
    result.push(chars[start..].iter().collect());
    result
}

pub(super) fn split_key_value(value: &str) -> Option<(String, String)> {
    let mut depth = 0i32;
    let mut quote = None;
    let mut at_scalar_start = true;
    let chars: Vec<char> = value.chars().collect();
    for (i, ch) in chars.iter().enumerate() {
        match quote {
            Some('\'') if *ch == '\'' => {
                if chars.get(i + 1) == Some(&'\'') {
                    continue;
                }
                quote = None;
            }
            Some('"') if *ch == '"' => quote = None,
            Some(_) => {}
            None => match ch {
                '\'' | '"' if at_scalar_start => {
                    quote = Some(*ch);
                    at_scalar_start = false;
                }
                '[' | '{' | '(' => {
                    depth += 1;
                    at_scalar_start = true;
                }
                ']' | '}' | ')' => {
                    depth -= 1;
                    at_scalar_start = false;
                }
                ',' => at_scalar_start = true,
                ':' if depth == 0 && (i + 1 == chars.len() || chars[i + 1].is_whitespace()) => {
                    return Some((
                        yaml_unquote(&chars[..i].iter().collect::<String>()),
                        chars[i + 1..].iter().collect::<String>().trim().to_string(),
                    ));
                }
                ':' => at_scalar_start = true,
                c if c.is_whitespace() => {}
                _ => at_scalar_start = false,
            },
        }
    }
    None
}

pub(super) fn yaml_inline(value: &str, line: usize) -> io::Result<YamlValue> {
    let value = value.trim();
    if value.starts_with('[') && value.ends_with(']') {
        let inner = &value[1..value.len() - 1];
        return Ok(YamlValue::Seq(if inner.trim().is_empty() {
            Vec::new()
        } else {
            split_top_level(inner, ',')
                .into_iter()
                .map(|v| Ok(YamlValue::Scalar(yaml_unquote(&v))))
                .collect::<io::Result<Vec<_>>>()?
        }));
    }
    if value.starts_with('{') && value.ends_with('}') {
        let inner = &value[1..value.len() - 1];
        let mut map = BTreeMap::new();
        if !inner.trim().is_empty() {
            for item in split_top_level(inner, ',') {
                let (key, val) = split_key_value(&item)
                    .ok_or_else(|| err(format!("YAML line {line}: malformed inline map")))?;
                if map.insert(key.clone(), yaml_inline(&val, line)?).is_some() {
                    return Err(err(format!("YAML line {line}: duplicate key {key:?}")));
                }
            }
        }
        return Ok(YamlValue::Map(map));
    }
    if value == "" || value == "null" || value == "~" {
        return Ok(YamlValue::Scalar(String::new()));
    }
    Ok(YamlValue::Scalar(yaml_unquote(value)))
}

pub(super) fn strip_yaml_comment(raw: &str) -> &str {
    let mut quote = None;
    for (i, ch) in raw.char_indices() {
        match quote {
            Some('\'') if ch == '\'' => quote = None,
            Some('"') if ch == '"' => quote = None,
            Some(_) => {}
            None if ch == '\'' || ch == '"' => quote = Some(ch),
            None if ch == '#' && (i == 0 || raw.as_bytes()[i - 1].is_ascii_whitespace()) => {
                return &raw[..i]
            }
            None => {}
        }
    }
    raw
}

pub(super) fn yaml_lines(text: &str) -> io::Result<Vec<YamlLine>> {
    let mut lines = Vec::new();
    for (index, raw) in text.lines().enumerate() {
        let line = strip_yaml_comment(raw.trim_end_matches('\r'));
        if line.trim().is_empty() || line.trim() == "---" {
            continue;
        }
        let indent = line.chars().take_while(|c| *c == ' ').count();
        if indent % 2 != 0 || line[..indent].contains('\t') {
            return Err(err(format!(
                "YAML line {}: expected 2-space indentation",
                index + 1
            )));
        }
        lines.push(YamlLine {
            number: index + 1,
            indent,
            text: line[indent..].trim_end().to_string(),
        });
    }
    Ok(lines)
}

pub(super) fn parse_yaml_block(
    lines: &[YamlLine],
    index: &mut usize,
    indent: usize,
) -> io::Result<YamlValue> {
    if *index >= lines.len() || lines[*index].indent != indent {
        return Err(err("YAML: missing block"));
    }
    let sequence = lines[*index].text == "-" || lines[*index].text.starts_with("- ");
    if sequence {
        let mut values = Vec::new();
        while *index < lines.len() && lines[*index].indent == indent {
            let line = &lines[*index];
            if !line.text.starts_with('-') {
                return Err(err(format!(
                    "YAML line {}: mixed map and list",
                    line.number
                )));
            }
            let rest = line.text[1..].trim();
            *index += 1;
            if rest.is_empty() {
                if *index < lines.len() && lines[*index].indent > indent {
                    values.push(parse_yaml_block(lines, index, lines[*index].indent)?);
                } else {
                    values.push(YamlValue::Scalar(String::new()));
                }
            } else if let Some((key, val)) = split_key_value(rest) {
                let mut map = BTreeMap::new();
                map.insert(key, yaml_inline(&val, line.number)?);
                if *index < lines.len() && lines[*index].indent > indent {
                    let child_indent = lines[*index].indent;
                    let child = parse_yaml_block(lines, index, child_indent)?;
                    let YamlValue::Map(child) = child else {
                        return Err(err(format!(
                            "YAML line {}: list map expected map",
                            line.number
                        )));
                    };
                    for (k, v) in child {
                        if map.insert(k.clone(), v).is_some() {
                            return Err(err(format!(
                                "YAML line {}: duplicate key {k:?}",
                                line.number
                            )));
                        }
                    }
                }
                values.push(YamlValue::Map(map));
            } else {
                values.push(yaml_inline(rest, line.number)?);
                if *index < lines.len() && lines[*index].indent > indent {
                    return Err(err(format!(
                        "YAML line {}: scalar list item cannot have children",
                        lines[*index].number
                    )));
                }
            }
        }
        return Ok(YamlValue::Seq(values));
    }

    let mut map = BTreeMap::new();
    while *index < lines.len() && lines[*index].indent == indent {
        let line = &lines[*index];
        if line.text.starts_with('-') {
            return Err(err(format!(
                "YAML line {}: mixed list and map",
                line.number
            )));
        }
        let (key, val) = split_key_value(&line.text)
            .ok_or_else(|| err(format!("YAML line {}: expected key: value", line.number)))?;
        *index += 1;
        let parsed = if val.is_empty() {
            if *index < lines.len() && lines[*index].indent > indent {
                parse_yaml_block(lines, index, lines[*index].indent)?
            } else {
                YamlValue::Scalar(String::new())
            }
        } else {
            yaml_inline(&val, line.number)?
        };
        if map.insert(key.clone(), parsed).is_some() {
            return Err(err(format!(
                "YAML line {}: duplicate key {key:?}",
                line.number
            )));
        }
    }
    Ok(YamlValue::Map(map))
}

pub(super) fn parse_yaml(text: &str) -> io::Result<YamlValue> {
    let lines = yaml_lines(text)?;
    if lines.is_empty() {
        return Err(err("YAML lockfile is empty"));
    }
    let mut index = 0;
    let value = parse_yaml_block(&lines, &mut index, lines[0].indent)?;
    if index != lines.len() {
        return Err(err(format!(
            "YAML line {}: unexpected indentation",
            lines[index].number
        )));
    }
    Ok(value)
}

pub(super) fn yaml_map<'a>(
    value: &'a YamlValue,
    context: &str,
) -> io::Result<&'a BTreeMap<String, YamlValue>> {
    match value {
        YamlValue::Map(map) => Ok(map),
        _ => Err(err(format!("{context} must be a map"))),
    }
}

pub(super) fn yaml_str<'a>(value: Option<&'a YamlValue>) -> Option<&'a str> {
    match value {
        Some(YamlValue::Scalar(value)) => Some(value),
        _ => None,
    }
}

pub(super) fn yaml_bool(value: Option<&YamlValue>) -> bool {
    yaml_str(value) == Some("true")
}

pub(super) fn yaml_list(value: Option<&YamlValue>) -> Vec<String> {
    match value {
        Some(YamlValue::Seq(values)) => values
            .iter()
            .filter_map(|value| yaml_str(Some(value)).map(str::to_string))
            .collect(),
        Some(YamlValue::Scalar(value)) if !value.is_empty() => vec![value.to_string()],
        _ => Vec::new(),
    }
}

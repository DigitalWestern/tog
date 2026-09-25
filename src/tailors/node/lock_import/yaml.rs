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
    split_key_value_raw(value).map(|(key, value)| (yaml_unquote(&key), value))
}

/// Split `key: value` at its separator, leaving the key as written so the
/// lock reader can hold it to the rules for a scalar.
fn split_key_value_raw(value: &str) -> Option<(String, String)> {
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
                        chars[..i].iter().collect::<String>(),
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

/// YAML that pnpm never writes but a hand edit can produce. Reading it as
/// a plain string would give tog a different lock from the one pnpm reads,
/// so it is refused on its own line.
fn unsupported(line: usize, what: &str) -> io::Error {
    err(format!(
        "pnpm-lock.yaml line {line}: {what}, which pnpm never writes; undo the hand edit or run 'pnpm install' to rewrite the lock"
    ))
}

/// One scalar, key or value, as YAML reads it. A quoted scalar closes
/// exactly once and a double-quoted one holds only the escapes YAML
/// defines. A plain scalar may not begin with an indicator YAML gives
/// another meaning, and inside a flow collection it may not hold a bracket
/// or brace.
fn yaml_scalar(raw: &str, line: usize, flow: bool) -> io::Result<String> {
    let value = raw.trim();
    let word = value.split_whitespace().next().unwrap_or_default();
    match value.chars().next() {
        Some('\'') => single_quoted(value, line),
        Some('"') => double_quoted(value, line),
        Some('&') => Err(unsupported(line, &format!("an anchor ({word})"))),
        Some('*') => Err(unsupported(line, &format!("an alias ({word})"))),
        Some('!') => Err(unsupported(line, &format!("a tag ({word})"))),
        Some('|' | '>') => Err(unsupported(line, &format!("a block scalar ({word})"))),
        Some('[' | '{') => Err(unsupported(
            line,
            &format!("a flow collection that is unclosed or has text after it ({value})"),
        )),
        _ if flow && value.contains(['[', ']', '{', '}']) => Err(unsupported(
            line,
            &format!("a stray bracket or brace in a flow collection ({value})"),
        )),
        _ => Ok(value.to_string()),
    }
}

/// A plain value holding `: ` mid-value is a mapping in YAML, not a
/// string. A trailing colon (`catalog:`) is left to the scalar.
fn refuse_plain_mapping(value: &str, line: usize) -> io::Result<()> {
    let mapping = !value.starts_with(['\'', '"'])
        && value
            .char_indices()
            .any(|(index, ch)| ch == ':' && value[index + 1..].starts_with(char::is_whitespace));
    if mapping {
        return Err(unsupported(
            line,
            &format!("a mapping inside a plain value ({value})"),
        ));
    }
    Ok(())
}

fn after_closing_quote(value: String, rest: &str, line: usize) -> io::Result<String> {
    if rest.is_empty() {
        Ok(value)
    } else {
        Err(unsupported(
            line,
            &format!("text after a closing quote ({rest})"),
        ))
    }
}

fn single_quoted(value: &str, line: usize) -> io::Result<String> {
    let mut out = String::new();
    let mut chars = value[1..].char_indices().peekable();
    while let Some((index, ch)) = chars.next() {
        if ch != '\'' {
            out.push(ch);
        } else if chars.peek().map(|&(_, next)| next) == Some('\'') {
            chars.next();
            out.push('\'');
        } else {
            return after_closing_quote(out, &value[index + 2..], line);
        }
    }
    Err(unsupported(
        line,
        &format!("an unterminated quoted scalar ({value})"),
    ))
}

fn double_quoted(value: &str, line: usize) -> io::Result<String> {
    let malformed = |escape: char| {
        unsupported(
            line,
            &format!("a malformed \\{escape} escape in a double-quoted scalar ({value})"),
        )
    };
    let mut out = String::new();
    let mut chars = value[1..].char_indices();
    while let Some((index, ch)) = chars.next() {
        match ch {
            '"' => return after_closing_quote(out, &value[index + 2..], line),
            '\\' => {
                let Some((_, escape)) = chars.next() else {
                    break;
                };
                let decoded = match escape {
                    '0' => '\0',
                    'a' => '\u{7}',
                    'b' => '\u{8}',
                    't' | '\t' => '\t',
                    'n' => '\n',
                    'v' => '\u{b}',
                    'f' => '\u{c}',
                    'r' => '\r',
                    'e' => '\u{1b}',
                    ' ' => ' ',
                    '"' => '"',
                    '/' => '/',
                    '\\' => '\\',
                    'N' => '\u{85}',
                    '_' => '\u{a0}',
                    'L' => '\u{2028}',
                    'P' => '\u{2029}',
                    'x' | 'u' | 'U' => {
                        let width = match escape {
                            'x' => 2,
                            'u' => 4,
                            _ => 8,
                        };
                        let mut code =
                            hex_escape(&mut chars, width).ok_or_else(|| malformed(escape))?;
                        // A UTF-16 surrogate pair spells one character across
                        // two `\u` escapes, as JSON writes it.
                        if escape == 'u' && (0xD800..0xDC00).contains(&code) {
                            let low = (chars.next().map(|(_, c)| c) == Some('\\')
                                && chars.next().map(|(_, c)| c) == Some('u'))
                            .then(|| hex_escape(&mut chars, 4))
                            .flatten()
                            .filter(|low| (0xDC00..0xE000).contains(low))
                            .ok_or_else(|| malformed(escape))?;
                            code = 0x10000 + ((code - 0xD800) << 10) + (low - 0xDC00);
                        }
                        char::from_u32(code).ok_or_else(|| malformed(escape))?
                    }
                    other => {
                        return Err(unsupported(
                            line,
                            &format!(
                                "an unknown escape \\{other} in a double-quoted scalar ({value})"
                            ),
                        ))
                    }
                };
                out.push(decoded);
            }
            _ => out.push(ch),
        }
    }
    Err(unsupported(
        line,
        &format!("an unterminated quoted scalar ({value})"),
    ))
}

fn hex_escape(chars: &mut std::str::CharIndices<'_>, width: usize) -> Option<u32> {
    let mut code = 0u32;
    for _ in 0..width {
        code = code * 16 + chars.next()?.1.to_digit(16)?;
    }
    Some(code)
}

pub(super) fn yaml_inline(value: &str, line: usize) -> io::Result<YamlValue> {
    yaml_value(value, line, false)
}

fn yaml_value(value: &str, line: usize, flow: bool) -> io::Result<YamlValue> {
    let value = value.trim();
    if value.starts_with('[') && value.ends_with(']') {
        let inner = &value[1..value.len() - 1];
        return Ok(YamlValue::Seq(if inner.trim().is_empty() {
            Vec::new()
        } else {
            split_top_level(inner, ',')
                .into_iter()
                .map(|item| flow_sequence_item(&item, line))
                .collect::<io::Result<Vec<_>>>()?
        }));
    }
    if value.starts_with('{') && value.ends_with('}') {
        let inner = &value[1..value.len() - 1];
        let mut map = BTreeMap::new();
        if !inner.trim().is_empty() {
            for item in split_top_level(inner, ',') {
                let (key, val) = split_key_value_raw(&item)
                    .ok_or_else(|| err(format!("YAML line {line}: malformed inline map")))?;
                let key = yaml_scalar(&key, line, true)?;
                if map
                    .insert(key.clone(), yaml_value(&val, line, true)?)
                    .is_some()
                {
                    return Err(err(format!("YAML line {line}: duplicate key {key:?}")));
                }
            }
        }
        return Ok(YamlValue::Map(map));
    }
    if value.is_empty() || value == "null" || value == "~" {
        return Ok(YamlValue::Scalar(String::new()));
    }
    let scalar = yaml_scalar(value, line, flow)?;
    refuse_plain_mapping(value, line)?;
    Ok(YamlValue::Scalar(scalar))
}

/// An item of a flow sequence is a scalar: the sequences pnpm writes inline
/// (`os`, `cpu`, `libc`) hold names, and a nested collection would be
/// dropped by readers that collect only scalars.
fn flow_sequence_item(item: &str, line: usize) -> io::Result<YamlValue> {
    let item = item.trim();
    if item.is_empty() {
        return Err(unsupported(line, "an empty item in a flow sequence"));
    }
    if item.starts_with(['[', '{']) {
        return Err(unsupported(
            line,
            &format!("a flow collection inside a flow sequence ({item})"),
        ));
    }
    let scalar = yaml_scalar(item, line, true)?;
    refuse_plain_mapping(item, line)?;
    Ok(YamlValue::Scalar(scalar))
}

/// The line without its comment. A `#` after whitespace outside a quoted
/// scalar opens a comment, and a quote opens a quoted scalar only where a
/// scalar can begin, as `split_key_value` reads it: the apostrophe in a
/// plain `it's` is an ordinary character.
pub(super) fn strip_yaml_comment(raw: &str) -> &str {
    let mut quote = None;
    let mut at_scalar_start = true;
    let mut chars = raw.char_indices().peekable();
    while let Some((i, ch)) = chars.next() {
        match quote {
            Some('\'') if ch == '\'' => {
                if chars.peek().map(|&(_, next)| next) == Some('\'') {
                    chars.next();
                } else {
                    quote = None;
                }
            }
            Some('"') if ch == '\\' => {
                chars.next();
            }
            Some('"') if ch == '"' => quote = None,
            Some(_) => {}
            None => match ch {
                '#' if i == 0 || raw.as_bytes()[i - 1].is_ascii_whitespace() => return &raw[..i],
                '\'' | '"' if at_scalar_start => {
                    quote = Some(ch);
                    at_scalar_start = false;
                }
                '-' | '?'
                    if at_scalar_start
                        && chars.peek().is_none_or(|&(_, next)| next.is_whitespace()) => {}
                '[' | '{' | '(' | ',' | ':' => at_scalar_start = true,
                c if c.is_whitespace() => {}
                _ => at_scalar_start = false,
            },
        }
    }
    raw
}

/// The document a pnpm lock is read from, and how many lines precede it.
/// `pnpm self-update` writes a prelude document for pnpm itself ahead of
/// the project's lock, so the project's lock is the last document, and
/// pnpm never writes a third.
pub(super) fn last_yaml_document(text: &str) -> io::Result<(usize, &str)> {
    let mut start = (0, 0);
    let mut documents = 0;
    let mut open = false;
    let mut offset = 0;
    for (index, raw) in text.split_inclusive('\n').enumerate() {
        let line = raw.trim_end_matches('\n').trim_end_matches('\r');
        let marker = line
            .strip_prefix("---")
            .filter(|rest| rest.is_empty() || rest.starts_with([' ', '\t']));
        offset += raw.len();
        if let Some(rest) = marker {
            if !strip_yaml_comment(rest).trim().is_empty() {
                return Err(unsupported(index + 1, "content after a document marker"));
            }
            documents += 1;
            open = true;
            start = (index + 1, offset);
            if documents > 2 {
                return Err(unsupported(index + 1, "a third YAML document"));
            }
        } else if !open && !strip_yaml_comment(line).trim().is_empty() {
            documents += 1;
            open = true;
        }
    }
    Ok((start.0, &text[start.1..]))
}

pub(super) fn yaml_lines(text: &str, first_line: usize) -> io::Result<Vec<YamlLine>> {
    let mut lines = Vec::new();
    for (index, raw) in text.lines().enumerate() {
        let number = first_line + index + 1;
        let line = strip_yaml_comment(raw.trim_end_matches('\r'));
        if line.trim().is_empty() {
            continue;
        }
        let indent = line.chars().take_while(|c| *c == ' ').count();
        if line[indent..].starts_with('\t') {
            return Err(unsupported(number, "a tab in the indentation"));
        }
        if indent % 2 != 0 {
            return Err(err(format!(
                "YAML line {number}: expected 2-space indentation"
            )));
        }
        lines.push(YamlLine {
            number,
            indent,
            text: line[indent..].trim_end().to_string(),
        });
    }
    Ok(lines)
}

/// A block key, held to the rules for a scalar, and its inline value.
fn block_key_value(text: &str, line: usize) -> io::Result<Option<(String, String)>> {
    match split_key_value_raw(text) {
        Some((key, value)) => Ok(Some((yaml_scalar(&key, line, false)?, value))),
        None => Ok(None),
    }
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
            } else if let Some((key, val)) = block_key_value(rest, line.number)? {
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
        let (key, val) = block_key_value(&line.text, line.number)?
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

/// Read a pnpm lock: its last document, with every line numbered as it
/// stands in the file.
pub(super) fn parse_yaml(text: &str) -> io::Result<YamlValue> {
    let (skipped, document) = last_yaml_document(text)?;
    let lines = yaml_lines(document, skipped)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn scalar(value: &str) -> YamlValue {
        YamlValue::Scalar(value.to_string())
    }

    fn map(entries: &[(&str, YamlValue)]) -> YamlValue {
        YamlValue::Map(
            entries
                .iter()
                .map(|(key, value)| (key.to_string(), value.clone()))
                .collect(),
        )
    }

    /// Each row is YAML pnpm never writes but a hand edit can produce.
    /// Reading any of them as a plain string would give tog a different
    /// lock from the one pnpm reads, so each is refused on its own line.
    #[test]
    fn yaml_pnpm_never_writes_is_refused_on_its_line() {
        for (case, text, line, expected) in [
            ("tab indentation", "a:\n\tb: 1\n", 2, "tab"),
            ("tab after spaces", "a:\n  \tb: 1\n", 2, "tab"),
            ("anchor value", "a: &x 1\n", 1, "anchor"),
            ("anchor key", "&x a: 1\n", 1, "anchor"),
            ("alias value", "a:\n  b: *x\n", 2, "alias"),
            ("alias list item", "a:\n  - *x\n", 2, "alias"),
            ("tag", "a: !!str 1\n", 1, "tag"),
            ("block scalar", "a: |\n", 1, "block scalar"),
            ("unclosed flow map", "a: {b: 1\n", 1, "unclosed"),
            ("unclosed flow sequence", "a: [b, c\n", 1, "unclosed"),
            ("text after a flow map", "a: {b: 1} c\n", 1, "unclosed"),
            ("stray closing bracket", "a: [b]]\n", 1, "bracket"),
            (
                "flow map in flow sequence",
                "a: [{b: 1}]\n",
                1,
                "flow sequence",
            ),
            (
                "flow sequence in flow sequence",
                "a: [[b]]\n",
                1,
                "flow sequence",
            ),
            ("unknown escape", "a: \"b\\qc\"\n", 1, "escape"),
            ("short hex escape", "a: \"\\x4\"\n", 1, "escape"),
            ("unterminated single quote", "a: 'b\n", 1, "unterminated"),
            ("unterminated double quote", "a: \"b\n", 1, "unterminated"),
            ("text after a quoted scalar", "a: 'b' c\n", 1, "after"),
            ("lone quote inside single quotes", "a: 'b'c'\n", 1, "after"),
            ("mapping inside a plain value", "a: b: c\n", 1, "mapping"),
            ("empty flow sequence item", "a: [b, ]\n", 1, "empty"),
            ("third document", "a: 1\n---\nb: 2\n---\nc: 3\n", 4, "third"),
        ] {
            let error = parse_yaml(text).expect_err(case).to_string();
            assert!(
                error.starts_with(&format!("pnpm-lock.yaml line {line}: ")),
                "{case}: {error}"
            );
            assert!(error.contains(expected), "{case}: {error}");
            assert!(error.contains("pnpm install"), "{case}: {error}");
        }
    }

    #[test]
    fn a_comment_after_a_mid_word_apostrophe_is_still_a_comment() {
        assert_eq!(
            parse_yaml("a: it's # note\nb: 'x # y' # note\nc: \"p\\\" # q\" # note\n").unwrap(),
            map(&[
                ("a", scalar("it's")),
                ("b", scalar("x # y")),
                ("c", scalar("p\" # q")),
            ])
        );
        assert_eq!(
            parse_yaml("l:\n  - 'x # y' # note\n  - it's # note\n").unwrap(),
            map(&[("l", YamlValue::Seq(vec![scalar("x # y"), scalar("it's")]))])
        );
    }

    #[test]
    fn double_quoted_scalars_decode_every_yaml_escape() {
        assert_eq!(
            parse_yaml(
                "a: \"\\x41\\t\\u00e9\\U0001F600\\ud83d\\ude00\\/\\\\\\\"\\0\\e\\N\\_\\L\\P\\ \\a\\v\"\n"
            )
            .unwrap(),
            map(&[(
                "a",
                scalar("A\t\u{e9}\u{1F600}\u{1F600}/\\\"\0\u{1b}\u{85}\u{a0}\u{2028}\u{2029} \u{7}\u{b}")
            )])
        );
    }

    #[test]
    fn only_the_last_yaml_document_is_read_and_lines_keep_their_file_numbers() {
        let text = "---\na: 1\nb: 2\n---\na: 3\n";
        assert_eq!(parse_yaml(text).unwrap(), map(&[("a", scalar("3"))]));
        let text = "---\na: 1\n--- # the main document\na: 3\nb: &x 1\n";
        let error = parse_yaml(text).unwrap_err().to_string();
        assert!(error.starts_with("pnpm-lock.yaml line 5: "), "{error}");
        assert_eq!(
            parse_yaml("a: 1\r\n---\r\na: 2\r\n").unwrap(),
            map(&[("a", scalar("2"))])
        );
        let error = parse_yaml("a: 1\n--- b: 2\n").unwrap_err().to_string();
        assert!(error.starts_with("pnpm-lock.yaml line 2: "), "{error}");
    }
}

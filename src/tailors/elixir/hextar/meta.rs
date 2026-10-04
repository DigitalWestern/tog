//! A Hex package's `metadata.config`, read as the Erlang terms it is: a
//! sequence of `{Key, Value}.` terms, which Hex writes with Erlang's
//! pretty printer, so one term may span several lines and nest lists,
//! tuples, maps and binaries (issue #359). The reader keeps what the lock
//! cross-check needs, the top-level binary keys with their binary values,
//! and refuses any text it cannot read rather than guess past it.

/// Nesting deeper than this is refused, so a hostile file cannot exhaust
/// the stack. Real metadata nests three or four levels.
const MAX_DEPTH: usize = 64;

/// One term, kept only as far as the cross-check looks into it.
#[derive(Debug, PartialEq, Eq)]
enum Term {
    Binary(Vec<u8>),
    Tuple(Vec<Term>),
    Other,
}

/// Every top-level `{<<"key">>, Value}` term in `text`, in order: the key's
/// bytes and, when the value is a binary, its bytes. A top-level term of
/// any other shape is skipped. Text that is not a sequence of `Term.`
/// is refused with where it stopped.
pub(super) fn top_level_entries(text: &str) -> Result<Vec<(Vec<u8>, Option<Vec<u8>>)>, String> {
    let mut reader = Reader {
        bytes: text.as_bytes(),
        at: 0,
    };
    let mut entries = Vec::new();
    loop {
        reader.skip_blank();
        if reader.at == reader.bytes.len() {
            return Ok(entries);
        }
        let term = reader.term(0)?;
        reader.skip_blank();
        if !reader.eat(b'.') {
            return Err(reader.error("a term does not end with '.'"));
        }
        if let Term::Tuple(mut items) = term {
            if items.len() == 2 {
                let value = items.pop();
                if let Some(Term::Binary(key)) = items.pop() {
                    let value = match value {
                        Some(Term::Binary(value)) => Some(value),
                        _ => None,
                    };
                    entries.push((key, value));
                }
            }
        }
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Reader<'_> {
    fn error(&self, what: &str) -> String {
        let line = 1 + self.bytes[..self.at]
            .iter()
            .filter(|&&b| b == b'\n')
            .count();
        format!("{what} (line {line})")
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.at).copied()
    }

    fn eat(&mut self, byte: u8) -> bool {
        if self.peek() == Some(byte) {
            self.at += 1;
            true
        } else {
            false
        }
    }

    fn eat_str(&mut self, text: &str) -> bool {
        if self.bytes[self.at..].starts_with(text.as_bytes()) {
            self.at += text.len();
            true
        } else {
            false
        }
    }

    /// Whitespace and `%` comments.
    fn skip_blank(&mut self) {
        while let Some(byte) = self.peek() {
            if byte.is_ascii_whitespace() {
                self.at += 1;
            } else if byte == b'%' {
                while self.peek().is_some_and(|b| b != b'\n') {
                    self.at += 1;
                }
            } else {
                break;
            }
        }
    }

    fn expect(&mut self, byte: u8) -> Result<(), String> {
        self.skip_blank();
        if self.eat(byte) {
            Ok(())
        } else {
            Err(self.error(&format!("expected '{}'", byte as char)))
        }
    }

    fn term(&mut self, depth: usize) -> Result<Term, String> {
        if depth > MAX_DEPTH {
            return Err(self.error("terms nest too deeply"));
        }
        self.skip_blank();
        match self.peek() {
            Some(b'{') => {
                self.at += 1;
                Ok(Term::Tuple(self.sequence(b'}', depth)?))
            }
            Some(b'[') => {
                self.at += 1;
                self.list(depth)
            }
            Some(b'#') => {
                self.at += 1;
                if !self.eat(b'{') {
                    return Err(self.error("expected '{' after '#'"));
                }
                self.map(depth)
            }
            Some(b'<') if self.eat_str("<<") => self.binary(),
            Some(b'"') => {
                self.at += 1;
                self.chars(b'"')?;
                Ok(Term::Other)
            }
            Some(b'\'') => {
                self.at += 1;
                self.chars(b'\'')?;
                Ok(Term::Other)
            }
            Some(b'$') => {
                self.at += 1;
                self.char_literal()?;
                Ok(Term::Other)
            }
            Some(byte) if byte.is_ascii_lowercase() => {
                while self
                    .peek()
                    .is_some_and(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'@')
                {
                    self.at += 1;
                }
                Ok(Term::Other)
            }
            Some(byte) if byte.is_ascii_digit() || byte == b'-' => self.number(),
            Some(_) => Err(self.error("unexpected character")),
            None => Err(self.error("the text ends inside a term")),
        }
    }

    /// Comma-separated terms up to `close`; an empty sequence is allowed.
    fn sequence(&mut self, close: u8, depth: usize) -> Result<Vec<Term>, String> {
        let mut items = Vec::new();
        self.skip_blank();
        if self.eat(close) {
            return Ok(items);
        }
        loop {
            items.push(self.term(depth + 1)?);
            self.skip_blank();
            if self.eat(close) {
                return Ok(items);
            }
            if !self.eat(b',') {
                return Err(self.error(&format!("expected ',' or '{}'", close as char)));
            }
        }
    }

    /// A list, proper or with a `| Tail`.
    fn list(&mut self, depth: usize) -> Result<Term, String> {
        self.skip_blank();
        if self.eat(b']') {
            return Ok(Term::Other);
        }
        loop {
            self.term(depth + 1)?;
            self.skip_blank();
            if self.eat(b']') {
                return Ok(Term::Other);
            }
            if self.eat(b'|') {
                self.term(depth + 1)?;
                self.expect(b']')?;
                return Ok(Term::Other);
            }
            if !self.eat(b',') {
                return Err(self.error("expected ',', '|' or ']'"));
            }
        }
    }

    /// The rest of a `#{K => V, ...}` map.
    fn map(&mut self, depth: usize) -> Result<Term, String> {
        self.skip_blank();
        if self.eat(b'}') {
            return Ok(Term::Other);
        }
        loop {
            self.term(depth + 1)?;
            self.skip_blank();
            if !self.eat_str("=>") {
                return Err(self.error("expected '=>' in a map"));
            }
            self.term(depth + 1)?;
            self.skip_blank();
            if self.eat(b'}') {
                return Ok(Term::Other);
            }
            if !self.eat(b',') {
                return Err(self.error("expected ',' or '}' in a map"));
            }
        }
    }

    /// The rest of a `<<...>>` binary: segments that are a string or a
    /// byte value, a string optionally typed `/utf8`. Any other size or
    /// type specifier is refused.
    fn binary(&mut self) -> Result<Term, String> {
        let mut bytes = Vec::new();
        self.skip_blank();
        if self.eat_str(">>") {
            return Ok(Term::Binary(bytes));
        }
        loop {
            self.skip_blank();
            if self.eat(b'"') {
                let chars = self.chars(b'"')?;
                if self.eat_str("/utf8") {
                    for code in chars {
                        let ch = char::from_u32(code)
                            .ok_or_else(|| self.error("a /utf8 binary holds a non-character"))?;
                        bytes.extend_from_slice(ch.encode_utf8(&mut [0; 4]).as_bytes());
                    }
                } else {
                    for code in chars {
                        bytes.push(
                            u8::try_from(code)
                                .map_err(|_| self.error("a binary character is over 255"))?,
                        );
                    }
                }
            } else {
                let start = self.at;
                while self.peek().is_some_and(|b| b.is_ascii_digit()) {
                    self.at += 1;
                }
                let value = std::str::from_utf8(&self.bytes[start..self.at])
                    .ok()
                    .and_then(|digits| digits.parse::<u8>().ok())
                    .ok_or_else(|| self.error("a binary segment is not a string or a byte"))?;
                bytes.push(value);
            }
            self.skip_blank();
            if self.eat_str(">>") {
                return Ok(Term::Binary(bytes));
            }
            if !self.eat(b',') {
                return Err(self.error("expected ',' or '>>' in a binary"));
            }
        }
    }

    /// The characters of a quoted string or atom up to `quote`, escapes
    /// decoded, as code points.
    fn chars(&mut self, quote: u8) -> Result<Vec<u32>, String> {
        let mut out = Vec::new();
        loop {
            match self.peek() {
                None => return Err(self.error("a quoted string never ends")),
                Some(byte) if byte == quote => {
                    self.at += 1;
                    return Ok(out);
                }
                Some(b'\\') => {
                    self.at += 1;
                    out.push(self.escape()?);
                }
                Some(_) => {
                    let rest = std::str::from_utf8(&self.bytes[self.at..])
                        .map_err(|_| self.error("not UTF-8"))?;
                    let ch = rest.chars().next().unwrap_or('\0');
                    self.at += ch.len_utf8();
                    out.push(ch as u32);
                }
            }
        }
    }

    /// `$c`: one character, possibly escaped.
    fn char_literal(&mut self) -> Result<u32, String> {
        match self.peek() {
            Some(b'\\') => {
                self.at += 1;
                self.escape()
            }
            Some(_) => {
                let rest = std::str::from_utf8(&self.bytes[self.at..])
                    .map_err(|_| self.error("not UTF-8"))?;
                let ch = rest.chars().next().unwrap_or('\0');
                self.at += ch.len_utf8();
                Ok(ch as u32)
            }
            None => Err(self.error("the text ends after '$'")),
        }
    }

    /// One escape, after its backslash, as Erlang reads it.
    fn escape(&mut self) -> Result<u32, String> {
        let Some(byte) = self.peek() else {
            return Err(self.error("the text ends inside an escape"));
        };
        self.at += 1;
        let code = match byte {
            b'b' => 8,
            b'd' => 127,
            b'e' => 27,
            b'f' => 12,
            b'n' => 10,
            b'r' => 13,
            b's' => 32,
            b't' => 9,
            b'v' => 11,
            b'0'..=b'7' => {
                let mut value = u32::from(byte - b'0');
                for _ in 0..2 {
                    match self.peek() {
                        Some(digit @ b'0'..=b'7') => {
                            self.at += 1;
                            value = value * 8 + u32::from(digit - b'0');
                        }
                        _ => break,
                    }
                }
                value
            }
            b'x' => {
                let braced = self.eat(b'{');
                let start = self.at;
                while self.peek().is_some_and(|b| b.is_ascii_hexdigit())
                    && (braced || self.at - start < 2)
                {
                    self.at += 1;
                }
                let digits = std::str::from_utf8(&self.bytes[start..self.at]).unwrap_or("");
                let value = u32::from_str_radix(digits, 16)
                    .map_err(|_| self.error("a \\x escape has no hex digits"))?;
                if braced && !self.eat(b'}') {
                    return Err(self.error("a \\x{...} escape is not closed"));
                }
                value
            }
            b'^' => {
                let Some(letter) = self.peek() else {
                    return Err(self.error("the text ends inside an escape"));
                };
                self.at += 1;
                u32::from(letter) & 31
            }
            other if other.is_ascii() => u32::from(other),
            _ => return Err(self.error("an escape of a non-ASCII byte")),
        };
        Ok(code)
    }

    /// An integer (`12`, `-3`, `16#ff`) or a float (`1.5`, `2.0e-3`). A
    /// `.` only belongs to the number when a digit follows it, so the
    /// term-ending dot after `12` stays for the caller.
    fn number(&mut self) -> Result<Term, String> {
        self.eat(b'-');
        let digits = |reader: &mut Self| {
            let start = reader.at;
            while reader
                .peek()
                .is_some_and(|b| b.is_ascii_alphanumeric() || b == b'_')
            {
                reader.at += 1;
            }
            reader.at > start
        };
        if !self.peek().is_some_and(|b| b.is_ascii_digit()) || !digits(self) {
            return Err(self.error("expected a number"));
        }
        if self.eat(b'#') && !digits(self) {
            return Err(self.error("a based integer has no digits"));
        }
        if self.peek() == Some(b'.')
            && self
                .bytes
                .get(self.at + 1)
                .is_some_and(|b| b.is_ascii_digit())
        {
            self.at += 1;
            digits(self);
            if matches!(self.bytes.get(self.at - 1), Some(b'e' | b'E'))
                && matches!(self.peek(), Some(b'-' | b'+'))
            {
                self.at += 1;
                digits(self);
            }
        }
        Ok(Term::Other)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entries(text: &str) -> Vec<(String, Option<String>)> {
        top_level_entries(text)
            .unwrap()
            .into_iter()
            .map(|(key, value)| {
                (
                    String::from_utf8(key).unwrap(),
                    value.map(|value| String::from_utf8(value).unwrap()),
                )
            })
            .collect()
    }

    /// jason 1.4.4's metadata.config as Hex serves it: terms span lines,
    /// and `requirements` nests another `app` tuple that is not top-level.
    const JASON: &str = r#"{<<"links">>,[{<<"GitHub">>,<<"https://github.com/michalmuskala/jason">>}]}.
{<<"name">>,<<"jason">>}.
{<<"version">>,<<"1.4.4">>}.
{<<"description">>,
 <<"A blazing fast JSON parser and generator in pure Elixir.">>}.
{<<"elixir">>,<<"~> 1.4">>}.
{<<"app">>,<<"jason">>}.
{<<"licenses">>,[<<"Apache-2.0">>]}.
{<<"requirements">>,
 [[{<<"name">>,<<"decimal">>},
   {<<"app">>,<<"decimal">>},
   {<<"optional">>,true},
   {<<"requirement">>,<<"~> 1.0 or ~> 2.0">>},
   {<<"repository">>,<<"hexpm">>}]]}.
{<<"files">>,
 [<<"lib">>,<<"lib/jason.ex">>,<<"mix.exs">>,<<"README.md">>,<<"LICENSE">>,
  <<"CHANGELOG.md">>]}.
{<<"build_tools">>,[<<"mix">>]}.
"#;

    #[test]
    fn real_metadata_reads_only_top_level_entries() {
        let read = entries(JASON);
        let get = |key: &str| -> Vec<Option<String>> {
            read.iter()
                .filter(|(k, _)| k == key)
                .map(|(_, v)| v.clone())
                .collect()
        };
        assert_eq!(get("app"), [Some("jason".to_string())]);
        assert_eq!(get("version"), [Some("1.4.4".to_string())]);
        assert_eq!(
            get("description"),
            [Some(
                "A blazing fast JSON parser and generator in pure Elixir.".to_string()
            )]
        );
        assert_eq!(get("requirements"), [None]);
        assert_eq!(read.len(), 10);
    }

    #[test]
    fn every_term_shape_hex_can_print_is_read() {
        let text = "% a comment\n\
            {<<\"app\">> , << \"caf\\x{e9}\"/utf8 >>} .\n\
            {<<\"bytes\">>,<<100,101,109,111>>}.\n\
            {<<\"latin\">>,<<\"\\351t\\351\">>}.\n\
            {<<\"map\">>,#{<<\"a\">> => [1,2|3], k => {1.5,-2.0e-3,16#ff,$a,$\\n}}}.\n\
            {<<\"atoms\">>,['quoted atom',true,\"chars\\\"q\"]}.\n\
            {<<\"empty\">>,<<>>}.\n\
            {not_a_binary_key,<<\"x\">>}.\n";
        let entry =
            |key: &str, value: Option<&[u8]>| (key.as_bytes().to_vec(), value.map(<[u8]>::to_vec));
        assert_eq!(
            top_level_entries(text).unwrap(),
            [
                entry("app", Some("café".as_bytes())),
                entry("bytes", Some(b"demo")),
                entry("latin", Some(&[0xe9, b't', 0xe9])),
                entry("map", None),
                entry("atoms", None),
                entry("empty", Some(b"")),
            ]
        );
    }

    #[test]
    fn unreadable_text_is_refused_with_its_line() {
        for (text, why) in [
            ("{<<\"app\">>,<<\"demo\">>}", "does not end with '.'"),
            ("{<<\"app\">>,<<\"demo\">>.\n", "expected ',' or '}'"),
            (
                "{<<\"app\">>,<<\"demo\"/latin1>>}.\n",
                "expected ',' or '>>'",
            ),
            ("{<<\"app\">>,<<300>>}.\n", "not a string or a byte"),
            ("{<<\"app\">>,<<\"\\x{110000}\"/utf8>>}.\n", "non-character"),
            ("\n\n{<<\"app\">>,@}.\n", "unexpected character (line 3)"),
            ("{<<\"app\">>,\"open}.\n", "never ends"),
        ] {
            let error = top_level_entries(text).unwrap_err();
            assert!(error.contains(why), "{text:?}: {error}");
        }
        let deep = format!("{}{}.", "[".repeat(100), "]".repeat(100));
        assert!(top_level_entries(&deep)
            .unwrap_err()
            .contains("nest too deeply"));
    }
}

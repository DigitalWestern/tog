//! PEP 508 environment-marker evaluation (python tailor) for lock
//! resolution: which of a package's dependencies apply on this platform.
//!
//! The marker is tokenized and parsed with PEP 508's grammar before anything
//! is evaluated, so a keyword without surrounding spaces
//! (`sys_platform=="linux"or ...`), an operator inside a quoted value, or an
//! empty group is read the way `packaging` reads it, or refused. A marker
//! tog cannot evaluate is an error, never a guess.

use super::*;

/// Evaluate the PEP 508 marker subset emitted by Poetry and uv lock files.
/// Lock variants must be filtered before graph traversal, so retaining the
/// marker text and handing it to an unconstrained resolver is not enough.
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
    // An absent marker applies everywhere; an empty group inside one is a
    // syntax error below.
    if expression.trim().is_empty() {
        return Ok(true);
    }
    let unsupported = |reason: &str| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported environment marker `{expression}`: {reason}"),
        )
    };
    let tokens = tokenize(expression).map_err(|reason| unsupported(&reason))?;
    let mut parser = Parser { tokens, next: 0 };
    let tree = parser.or().map_err(|reason| unsupported(&reason))?;
    if let Some(token) = parser.tokens.get(parser.next) {
        return Err(unsupported(&format!("unexpected {}", token.describe())));
    }
    let environment = Environment {
        python_version,
        platform,
        extra,
        expression,
    };
    environment.eval(&tree)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Token<'a> {
    Open,
    Close,
    Str(&'a str),
    Name(&'a str),
    Op(&'static str),
}

impl Token<'_> {
    fn describe(&self) -> String {
        match self {
            Token::Open => "`(`".into(),
            Token::Close => "`)`".into(),
            Token::Str(text) => format!("string '{text}'"),
            Token::Name(name) => format!("`{name}`"),
            Token::Op(op) => format!("`{op}`"),
        }
    }
}

/// Longest first, so `===` is not read as `==` and `<=` not as `<`.
const COMPARISONS: &[&str] = &["===", "==", "!=", "<=", ">=", "~=", "<", ">"];

/// A value runs to the next quote of the kind that opened it. `packaging`
/// reads a value as a Python string literal, so `'lin\x75x'` is `linux`
/// there; tog refuses backslashes and control characters rather than
/// decode them. Only spaces and tabs separate tokens, as in `packaging`.
fn tokenize(expression: &str) -> Result<Vec<Token<'_>>, String> {
    let bytes = expression.as_bytes();
    let mut tokens = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        let byte = bytes[at];
        if byte == b' ' || byte == b'\t' {
            at += 1;
        } else if byte == b'(' {
            tokens.push(Token::Open);
            at += 1;
        } else if byte == b')' {
            tokens.push(Token::Close);
            at += 1;
        } else if byte == b'\'' || byte == b'"' {
            let end = expression[at + 1..]
                .find(byte as char)
                .ok_or_else(|| "unterminated string".to_string())?;
            let value = &expression[at + 1..at + 1 + end];
            if value.contains(|c: char| c == '\\' || c.is_control()) {
                return Err(
                    "escapes and control characters are not supported in quoted values".into(),
                );
            }
            tokens.push(Token::Str(value));
            at += end + 2;
        } else if let Some(op) = COMPARISONS
            .iter()
            .find(|op| expression[at..].starts_with(**op))
        {
            tokens.push(Token::Op(op));
            at += op.len();
        } else if byte.is_ascii_alphanumeric() || byte == b'_' {
            // `.` for the legacy names `packaging` still reads (`sys.platform`).
            let start = at;
            while at < bytes.len()
                && (bytes[at].is_ascii_alphanumeric() || matches!(bytes[at], b'_' | b'.'))
            {
                at += 1;
            }
            tokens.push(Token::Name(&expression[start..at]));
        } else {
            let unexpected = expression[at..].chars().next().unwrap_or_default();
            return Err(format!(
                "unexpected character `{}`",
                unexpected.escape_debug()
            ));
        }
    }
    Ok(tokens)
}

#[derive(Debug)]
enum Tree<'a> {
    Or(Box<Tree<'a>>, Box<Tree<'a>>),
    And(Box<Tree<'a>>, Box<Tree<'a>>),
    Compare(Operand<'a>, &'static str, Operand<'a>),
}

#[derive(Clone, Copy, Debug)]
enum Operand<'a> {
    Variable(&'a str),
    Literal(&'a str),
}

struct Parser<'a> {
    tokens: Vec<Token<'a>>,
    next: usize,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<Token<'a>> {
        self.tokens.get(self.next).copied()
    }

    fn take(&mut self) -> Option<Token<'a>> {
        let token = self.peek();
        self.next += 1;
        token
    }

    fn keyword(&mut self, word: &str) -> bool {
        if self.peek() == Some(Token::Name(word)) {
            self.next += 1;
            true
        } else {
            false
        }
    }

    /// `or` of `and`s: `and` binds tighter.
    fn or(&mut self) -> Result<Tree<'a>, String> {
        let mut tree = self.and()?;
        while self.keyword("or") {
            tree = Tree::Or(Box::new(tree), Box::new(self.and()?));
        }
        Ok(tree)
    }

    fn and(&mut self) -> Result<Tree<'a>, String> {
        let mut tree = self.atom()?;
        while self.keyword("and") {
            tree = Tree::And(Box::new(tree), Box::new(self.atom()?));
        }
        Ok(tree)
    }

    fn atom(&mut self) -> Result<Tree<'a>, String> {
        if self.peek() == Some(Token::Open) {
            self.next += 1;
            let tree = self.or()?;
            return match self.take() {
                Some(Token::Close) => Ok(tree),
                Some(token) => Err(format!("expected `)`, found {}", token.describe())),
                None => Err("unclosed `(`".into()),
            };
        }
        let left = self.operand()?;
        let op = match self.take() {
            Some(Token::Op(op)) => op,
            Some(Token::Name("in")) => "in",
            Some(Token::Name("not")) if self.keyword("in") => "not in",
            Some(token) => {
                return Err(format!("expected a comparison, found {}", token.describe()))
            }
            None => return Err("expected a comparison".into()),
        };
        Ok(Tree::Compare(left, op, self.operand()?))
    }

    fn operand(&mut self) -> Result<Operand<'a>, String> {
        match self.take() {
            Some(Token::Str(text)) => Ok(Operand::Literal(text)),
            Some(Token::Name(name)) if !matches!(name, "and" | "or" | "not" | "in") => {
                Ok(Operand::Variable(name))
            }
            Some(token) => Err(format!("expected a value, found {}", token.describe())),
            None => Err("expected a value".into()),
        }
    }
}

struct Environment<'a> {
    python_version: &'a str,
    platform: Platform,
    extra: Option<&'a str>,
    expression: &'a str,
}

impl Environment<'_> {
    fn eval(&self, tree: &Tree) -> io::Result<bool> {
        match tree {
            // Both sides are evaluated, so a marker tog cannot read is an
            // error even where the other side already decides the answer.
            Tree::Or(left, right) => Ok(self.eval(left)? | self.eval(right)?),
            Tree::And(left, right) => Ok(self.eval(left)? & self.eval(right)?),
            Tree::Compare(left, op, right) => self.compare(*left, op, *right),
        }
    }

    fn value(&self, operand: Operand) -> io::Result<String> {
        match operand {
            Operand::Literal(text) => Ok(text.to_string()),
            Operand::Variable(
                name @ ("platform_release" | "platform_version" | "platform.version"),
            ) => kernel_value(name, self.platform).map_err(|why| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unsupported environment marker operand `{name}`: {why}"),
                )
            }),
            Operand::Variable(name) => {
                marker_value(name, self.python_version, self.platform, self.extra).ok_or_else(
                    || {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("unsupported environment marker operand `{name}`"),
                        )
                    },
                )
            }
        }
    }

    /// `packaging`'s rules: `in` is string membership; any other operator
    /// compares versions when `op value` is a PEP 440 specifier, and strings
    /// otherwise. Unlike `packaging`, ordering two non-versions is refused
    /// rather than compared as strings.
    fn compare(&self, left: Operand, op: &str, right: Operand) -> io::Result<bool> {
        let mut left_value = self.value(left)?;
        let mut right_value = self.value(right)?;
        let unsupported = |why: String| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "unsupported environment marker `{}`: {why}",
                    self.expression
                ),
            )
        };
        if matches!(left, Operand::Variable(_)) == matches!(right, Operand::Variable(_)) {
            return Err(unsupported(
                "a comparison needs one marker variable and one quoted value".into(),
            ));
        }
        let extra = matches!(left, Operand::Variable("extra"))
            || matches!(right, Operand::Variable("extra"));
        if extra {
            // PEP 685: extras compare by their normalized names.
            left_value = normalized_extra(&left_value);
            right_value = normalized_extra(&right_value);
        }
        match op {
            // An extra is a name, never a version: `extra == '01'` does not
            // match the extra `1`. `packaging` compares them as versions
            // here; uv, which writes the lock, compares names and ignores
            // any other operator with a warning, `in` and `not in` included.
            // Tog refuses those: ignoring one could install what the marker
            // excludes, and `packaging`'s substring rule disagrees with uv.
            "==" if extra => return Ok(left_value == right_value),
            "!=" if extra => return Ok(left_value != right_value),
            _ if extra => {
                return Err(unsupported(format!(
                    "`{op}` cannot compare extra names; use `==` or `!=`"
                )))
            }
            "in" => return Ok(right_value.contains(left_value.as_str())),
            "not in" => return Ok(!right_value.contains(left_value.as_str())),
            _ => {}
        }
        let as_versions =
            crate::kernel::pep440::marker_version_matches(op, &right_value, &left_value)?;
        match (as_versions, op) {
            (Some(result), _) => Ok(result),
            (None, "==") => Ok(left_value == right_value),
            (None, "!=") => Ok(left_value != right_value),
            (None, _) => Err(unsupported(format!(
                "`{op}` compares versions, and `{right_value}` is not a PEP 440 version"
            ))),
        }
    }
}

/// PEP 685 / PEP 503 name normalization: lower case, and every run of `-`,
/// `_` or `.` becomes one `-` (kept at the ends, as `packaging` does).
/// Lower case is Unicode's, as Python's `str.lower`: the Kelvin sign
/// (U+212A) is `k`.
fn normalized_extra(name: &str) -> String {
    let mut normalized = String::with_capacity(name.len());
    for c in name.chars() {
        if matches!(c, '-' | '_' | '.') {
            if !normalized.ends_with('-') {
                normalized.push('-');
            }
        } else {
            normalized.push(c);
        }
    }
    // Whole-string, so context-dependent rules apply (a final `Σ` is `ς`).
    normalized.to_lowercase()
}

/// `platform_release` and `platform_version` are the running kernel's
/// `uname -r` and `uname -v` (Python's `platform.release()` and
/// `platform.version()`), so they are known only when the target is this
/// host. For any other target the marker is refused, never guessed.
fn kernel_value(name: &str, platform: Platform) -> Result<String, String> {
    #[cfg(test)]
    if let Some((host, release, version)) = TEST_HOST_KERNEL.with(|slot| slot.borrow().clone()) {
        return kernel_field(name, platform, host, || Ok((release, version)));
    }
    let host = Platform::host().map_err(|error| error.to_string())?;
    kernel_field(name, platform, host, uname)
}

/// This host's kernel release and version, the two values `kernel_value`
/// hands a marker. The closure records them when a lock names either, so a
/// later run under another kernel is seen as a change.
pub(super) fn host_kernel() -> io::Result<(String, String)> {
    #[cfg(test)]
    if let Some((_, release, version)) = TEST_HOST_KERNEL.with(|slot| slot.borrow().clone()) {
        return Ok((release, version));
    }
    uname()
}

/// Whether a lock's text names a marker variable `kernel_value` answers.
pub(super) fn names_kernel_marker(lock: &str) -> bool {
    ["platform_release", "platform_version", "platform.version"]
        .iter()
        .any(|name| lock.contains(name))
}

fn kernel_field(
    name: &str,
    platform: Platform,
    host: Platform,
    read: impl FnOnce() -> io::Result<(String, String)>,
) -> Result<String, String> {
    if platform != host {
        return Err(format!(
            "it describes the running kernel, so it is known only when the target is \
             this host ({}), not {}",
            host.triple(),
            platform.triple()
        ));
    }
    let (release, version) = read().map_err(|error| format!("uname: {error}"))?;
    Ok(if name == "platform_release" {
        release
    } else {
        version
    })
}

/// The running kernel's release and version, as `uname(2)` reports them.
fn uname() -> io::Result<(String, String)> {
    let mut name = std::mem::MaybeUninit::<libc::utsname>::uninit();
    // SAFETY: uname fills the buffer it is given when it returns 0.
    if unsafe { libc::uname(name.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: uname returned 0, so every field is a NUL-terminated string.
    let name = unsafe { name.assume_init() };
    let field = |chars: &[libc::c_char]| {
        // SAFETY: the field is NUL-terminated within its array.
        unsafe { std::ffi::CStr::from_ptr(chars.as_ptr()) }
            .to_string_lossy()
            .into_owned()
    };
    Ok((field(&name.release), field(&name.version)))
}

#[cfg(test)]
thread_local! {
    /// A test's stand-in for the host and its `uname`.
    static TEST_HOST_KERNEL: std::cell::RefCell<Option<(Platform, String, String)>> =
        const { std::cell::RefCell::new(None) };
}

fn marker_value(
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
    // The legacy spellings `packaging` still accepts.
    let name = match name {
        "sys.platform" => "sys_platform",
        "os.name" => "os_name",
        "platform.machine" => "platform_machine",
        "platform.python_implementation" | "python_implementation" => {
            "platform_python_implementation"
        }
        name => name,
    };
    Some(match name {
        "python_version" => python_version,
        // CPython's implementation version is its Python version.
        "python_full_version" | "implementation_version" => python_full_version,
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

/// The marker grammar decides which locked packages install on this host,
/// so a wrong answer installs or drops a dependency silently. Each case
/// below is one rule of the subset tog evaluates; the refusals name the
/// part tog does not understand instead of guessing.
#[cfg(test)]
mod marker_tests {
    use super::*;

    const LINUX: Platform = Platform::X86_64UnknownLinuxGnu;
    const MAC: Platform = Platform::Aarch64AppleDarwin;

    fn eval(marker: &str, platform: Platform, extra: Option<&str>) -> bool {
        marker_matches_for_extra(marker, "3.12.14", platform, extra)
            .unwrap_or_else(|error| panic!("{marker}: {error}"))
    }

    fn refused(marker: &str) -> String {
        let error = marker_matches(marker, "3.12.14", LINUX).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{error}");
        error.to_string()
    }

    #[test]
    fn and_binds_tighter_than_or_and_parens_regroup() {
        let cases = [
            // `or` of (`and`): true or (false and false).
            (
                "sys_platform == 'linux' or sys_platform == 'win32' and python_version < '3'",
                true,
            ),
            // Parenthesised the other way: (true or false) and false.
            (
                "(sys_platform == 'linux' or sys_platform == 'win32') and python_version < '3'",
                false,
            ),
            ("sys_platform == 'win32' or sys_platform == 'linux'", true),
            ("sys_platform == 'win32' and sys_platform == 'linux'", false),
            ("sys_platform == 'linux' and python_version >= '3.12'", true),
            ("((sys_platform == 'linux'))", true),
            (
                "(sys_platform == 'linux') and (python_version < '3')",
                false,
            ),
            ("", true),
            ("   ", true),
        ];
        for (marker, expected) in cases {
            assert_eq!(eval(marker, LINUX, None), expected, "{marker}");
        }
    }

    /// PEP 508 needs no space around `and`/`or` next to a quote or a
    /// parenthesis. Split on spaces, these read as one comparison whose
    /// value swallowed the rest, and answered the opposite.
    #[test]
    fn keywords_need_no_surrounding_spaces() {
        let cases = [
            ("sys_platform==\"linux\"or sys_platform==\"darwin\"", true),
            ("sys_platform!=\"linux\"and sys_platform!=\"win32\"", false),
            ("(sys_platform=='win32')or(sys_platform=='linux')", true),
            ("python_version>='3.8'and(extra=='x'or extra=='y')", false),
        ];
        for (marker, expected) in cases {
            assert_eq!(eval(marker, LINUX, None), expected, "{marker}");
        }
    }

    /// Quoted values are data: keywords and operators inside them are not
    /// syntax, and a backslash is an ordinary character (PEP 508 has no
    /// escapes).
    #[test]
    fn quoted_values_are_opaque() {
        let cases = [
            ("sys_platform == 'linux or darwin'", false),
            ("sys_platform != 'linux and darwin'", true),
            ("sys_platform != 'linux=='", true),
            ("sys_platform == 'linux in darwin'", false),
            ("sys_platform == \"it's\"", false),
            ("'' in sys_platform", true),
        ];
        for (marker, expected) in cases {
            assert_eq!(eval(marker, LINUX, None), expected, "{marker}");
        }
    }

    #[test]
    fn platform_markers_follow_the_target_platform() {
        let cases = [
            ("platform_machine == 'x86_64'", true, false),
            ("platform_machine == 'arm64'", false, true),
            ("sys_platform == 'linux'", true, false),
            ("sys_platform == 'darwin'", false, true),
            ("platform_system == 'Linux'", true, false),
            ("platform_system == 'Darwin'", false, true),
            ("os_name == 'posix'", true, true),
            ("implementation_name == 'cpython'", true, true),
            ("platform_python_implementation == 'CPython'", true, true),
            ("'x86' in platform_machine", true, false),
            ("'x86' not in platform_machine", false, true),
        ];
        for (marker, linux, mac) in cases {
            assert_eq!(eval(marker, LINUX, None), linux, "{marker} on Linux");
            assert_eq!(eval(marker, MAC, None), mac, "{marker} on macOS");
        }
    }

    /// Extras compare by normalized name (PEP 685), on either side.
    #[test]
    fn extra_matches_only_the_requested_extra() {
        let marker = "extra == 'test'";
        assert!(eval(marker, LINUX, Some("test")));
        assert!(!eval(marker, LINUX, Some("docs")));
        assert!(!eval(marker, LINUX, None));
        assert!(eval("extra != 'test'", LINUX, None));
        for (marker, requested) in [
            ("extra == 'Foo_Bar'", "foo-bar"),
            ("extra == 'foo-bar'", "Foo.Bar"),
            ("'FOO__bar' == extra", "foo-bar"),
            ("extra == 'foo-_.bar'", "foo_bar"),
        ] {
            assert!(eval(marker, LINUX, Some(requested)), "{marker} {requested}");
        }
        assert!(!eval("extra == 'foobar'", LINUX, Some("foo-bar")));
        assert!(eval(
            "python_version >= '3.8' and extra == 'test'",
            LINUX,
            Some("test")
        ));
        assert!(!eval(
            "python_version < '3.8' and extra == 'test'",
            LINUX,
            Some("test")
        ));
    }

    /// Python versions compare as PEP 440 versions, not strings (as strings
    /// "3.12" < "3.9"), and pre-releases compare like any other version.
    #[test]
    fn python_versions_compare_as_versions() {
        let cases = [
            ("python_version >= '3.9'", true),
            ("python_version > '3.9'", true),
            ("python_version < '3.9'", false),
            ("'3.9' < python_version", true),
            ("'3.13.0rc1' > python_full_version", true),
            ("python_full_version < '3.13.0rc1'", true),
            ("python_full_version >= '3.12.14rc1'", true),
            ("python_full_version ~= '3.12.0'", true),
            ("python_version ~= '3.13'", false),
            ("python_version == '3.12.*'", true),
            ("python_full_version === '3.12.14'", true),
            ("python_full_version === '3.12.14.0'", false),
            ("python_full_version == '3.12.14.0'", true),
        ];
        for (marker, expected) in cases {
            assert_eq!(eval(marker, LINUX, None), expected, "{marker}");
        }
    }

    #[test]
    fn markers_tog_does_not_understand_are_refused() {
        let syntax = [
            ("sys_platform", "expected a comparison"),
            ("()", "expected a value, found `)`"),
            ("sys_platform == 'win32' or", "expected a value"),
            (
                "sys_platform == 'win32' or ()",
                "expected a value, found `)`",
            ),
            ("(sys_platform == 'linux'", "unclosed `(`"),
            (
                "(sys_platform == 'linux' 'x')",
                "expected `)`, found string 'x'",
            ),
            ("sys_platform == 'linux')", "unexpected `)`"),
            (
                "sys_platform == 'linux' sys_platform == 'linux'",
                "unexpected `sys_platform`",
            ),
            (
                "not sys_platform == 'win32'",
                "expected a value, found `not`",
            ),
            ("sys_platform == 'linux", "unterminated string"),
            ("sys_platform <> 'linux'", "expected a value, found `>`"),
            ("sys_platform = 'linux'", "unexpected character `=`"),
            (
                "sys_platform == 'linux' && os_name == 'posix'",
                "unexpected character `&`",
            ),
            ("sys_platform in and", "expected a value, found `and`"),
        ];
        for (marker, reason) in syntax {
            assert_eq!(
                refused(marker),
                format!("unsupported environment marker `{marker}`: {reason}"),
                "{marker}"
            );
        }
        assert_eq!(
            refused("platform_kernel >= '5'"),
            "unsupported environment marker operand `platform_kernel`"
        );
        assert_eq!(
            refused("sys_platform == linux"),
            "unsupported environment marker operand `linux`"
        );
        // Both sides are evaluated: an unknown marker is refused even where
        // the other side of `or` already decides the answer.
        assert_eq!(
            refused("sys_platform == 'linux' or platform_kernel == '1'"),
            "unsupported environment marker operand `platform_kernel`"
        );
        assert_eq!(
            refused("sys_platform == 'win32' and platform_kernel == '1'"),
            "unsupported environment marker operand `platform_kernel`"
        );
        // Ordering needs a version on the right; `packaging` would compare
        // these as strings, tog refuses.
        for (marker, value) in [
            ("sys_platform ~= 'linux'", "linux"),
            ("sys_platform < 'linux'", "linux"),
            ("sys_platform <= 'linux'", "linux"),
            ("sys_platform > 'linux'", "linux"),
            ("sys_platform >= 'linux'", "linux"),
            ("python_version >= 'three'", "three"),
            ("python_version >= '3.8,<4'", "3.8,<4"),
            ("python_version >= '3.8 <4'", "3.8 <4"),
            ("sys_platform === 'linux x'", "linux x"),
        ] {
            let op = marker.split(' ').nth(1).unwrap();
            assert_eq!(
                refused(marker),
                format!(
                    "unsupported environment marker `{marker}`: `{op}` compares versions, and `{value}` is not a PEP 440 version"
                )
            );
        }
        // A version specifier on the right needs a version on the left.
        for marker in ["sys_platform === 'linux'", "sys_platform == '1.0'"] {
            assert_eq!(
                refused(marker),
                "environment marker: invalid PEP 440 version `linux`: release segment is missing"
            );
        }
        for marker in ["sys_platform == sys_platform", "'linux' == 'linux'"] {
            assert_eq!(
                refused(marker),
                format!(
                    "unsupported environment marker `{marker}`: a comparison needs one marker variable and one quoted value"
                )
            );
        }
        let reason = "escapes and control characters are not supported in quoted values";
        for marker in [
            "sys_platform == 'lin\\x75x'",
            "sys_platform == 'lin\nux'",
            "sys_platform == 'lin\0ux'",
        ] {
            assert_eq!(
                refused(marker),
                format!("unsupported environment marker `{marker}`: {reason}")
            );
        }
        assert_eq!(
            refused("sys_platform\n== 'linux'"),
            "unsupported environment marker `sys_platform\n== 'linux'`: unexpected character `\\n`"
        );
        // `platform.version` is a legacy spelling `packaging` accepts;
        // `platform.release` never was one.
        assert_eq!(
            refused("platform.release == '1'"),
            "unsupported environment marker operand `platform.release`"
        );
    }

    /// Run `body` with `host` standing in for this machine, whose kernel
    /// reports `release` and `version`.
    fn on_host<T>(host: Platform, release: &str, version: &str, body: impl FnOnce() -> T) -> T {
        TEST_HOST_KERNEL
            .with(|slot| *slot.borrow_mut() = Some((host, release.into(), version.into())));
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(body));
        TEST_HOST_KERNEL.with(|slot| *slot.borrow_mut() = None);
        result.unwrap_or_else(|panic| std::panic::resume_unwind(panic))
    }

    /// A project whose `uv.lock` names a kernel marker records the kernel
    /// it was read under, and one that names none records nothing.
    #[test]
    fn a_lock_naming_a_kernel_marker_records_the_host_kernel() {
        use crate::kernel::fsroot::ProjectRoot;
        let temp = crate::kernel::testutil::TempDir::new();
        let project = ProjectRoot::open(&temp.0).unwrap();
        on_host(LINUX, "7.2.5", "#1 SMP", || {
            assert_eq!(super::super::kernel_marker_record(&project).unwrap(), None);
            std::fs::write(
                temp.0.join("uv.lock"),
                "marker = \"sys_platform == 'linux'\"\n",
            )
            .unwrap();
            assert_eq!(super::super::kernel_marker_record(&project).unwrap(), None);
            std::fs::write(
                temp.0.join("uv.lock"),
                "marker = \"platform_release == '7.2.5'\"\n",
            )
            .unwrap();
            assert_eq!(
                super::super::kernel_marker_record(&project).unwrap(),
                Some(serde_json::json!({"release": "7.2.5", "version": "#1 SMP"}))
            );
        });
        on_host(LINUX, "7.3.0", "#1 SMP", || {
            assert_eq!(
                super::super::kernel_marker_record(&project)
                    .unwrap()
                    .unwrap()["release"],
                "7.3.0"
            );
        });
    }

    /// `platform_release` and `platform_version` are the host kernel's, as
    /// `packaging` reads them, and refused for a target that is not the
    /// host. A kernel release that is not a PEP 440 version compares as a
    /// string by `==`, and ordering it is refused, as `packaging` raises.
    #[test]
    fn kernel_markers_are_the_hosts_and_refused_across_targets() {
        on_host(MAC, "23.4.0", "Darwin Kernel Version 23.4.0", || {
            assert!(eval("platform_release >= '22.0'", MAC, None));
            assert!(!eval("platform_release < '22.0'", MAC, None));
            assert!(eval(
                "platform_version == 'Darwin Kernel Version 23.4.0'",
                MAC,
                None
            ));
            assert!(eval(
                "platform.version == 'Darwin Kernel Version 23.4.0'",
                MAC,
                None
            ));
            assert!(eval("'Darwin' in platform_version", MAC, None));
            for marker in ["platform_release >= '22.0'", "platform_version == '1'"] {
                let name = marker.split(' ').next().unwrap();
                assert_eq!(
                    refused(marker),
                    format!(
                        "unsupported environment marker operand `{name}`: it describes the \
                         running kernel, so it is known only when the target is this host \
                         (aarch64-apple-darwin), not x86_64-unknown-linux-gnu"
                    )
                );
            }
        });
        on_host(
            LINUX,
            "7.2.5-200.fc44.x86_64",
            "#1 SMP PREEMPT_DYNAMIC",
            || {
                assert!(eval(
                    "platform_release == '7.2.5-200.fc44.x86_64'",
                    LINUX,
                    None
                ));
                assert!(eval("'fc44' in platform_release", LINUX, None));
                assert!(eval(
                    "platform_version == '#1 SMP PREEMPT_DYNAMIC'",
                    LINUX,
                    None
                ));
                for marker in ["platform_release >= '5.0'", "platform_release != '7.2.5'"] {
                    assert_eq!(
                        refused(marker),
                        "environment marker: invalid PEP 440 version `7.2.5-200.fc44.x86_64`: \
                         unrecognized version suffix `-200.fc44.x86_64`",
                        "{marker}"
                    );
                }
            },
        );
        // Without a stand-in, the values are this machine's own `uname`.
        let host = Platform::host().unwrap();
        let (release, _) = uname().unwrap();
        assert!(!release.is_empty());
        assert!(eval(
            &format!("platform_release == '{release}'"),
            host,
            None
        ));
    }

    /// `packaging`'s dispatch: `op value` that is a PEP 440 specifier
    /// compares versions, anything else compares strings.
    #[test]
    fn comparisons_follow_packaging() {
        let cases = [
            ("python_version == '*'", false),
            ("python_version != '*'", true),
            ("python_version != 'banana'", true),
            ("python_version == 'banana'", false),
            ("python_full_version == '3.12.14 >=3'", false),
            ("python_version == '3.12||3.13'", false),
            ("python_version == '3.12,3.13'", false),
            ("python_version == ' 3.12 '", true),
            ("python_full_version === '3.12.14'", true),
            ("python_full_version === '3.12.14.0'", false),
            ("implementation_version >= '3.12'", true),
            ("sys_platform == 'win32'", false),
            ("sys.platform == 'linux'", true),
            ("os.name == 'posix'", true),
            ("platform.machine == 'x86_64'", true),
            ("python_implementation == 'CPython'", true),
            ("platform.python_implementation == 'CPython'", true),
        ];
        for (marker, expected) in cases {
            assert_eq!(eval(marker, LINUX, None), expected, "{marker}");
        }
        let rc = |marker: &str| marker_matches(marker, "3.13.0RC1", LINUX).unwrap();
        assert!(rc("python_full_version === '3.13.0rc1'"));
        // PEP 440: `<V` never admits a pre-release of V itself.
        assert!(!rc("python_full_version < '3.13.0'"));
        assert!(rc("python_full_version < '3.13.1'"));
        // Extras keep separators at the ends.
        assert!(!eval("extra == '-foo-'", LINUX, Some("foo")));
        assert!(!eval("extra == '-foo'", LINUX, Some("foo")));
        assert!(!eval("extra == 'foo'", LINUX, Some("foo_")));
        assert!(eval("extra == '-foo-'", LINUX, Some("_Foo.")));
        assert!(eval("extra == '\u{212A}'", LINUX, Some("k")));
        assert!(eval("extra == 'ος'", LINUX, Some("ΟΣ")));
        assert!(eval("'v3.12.14' === python_full_version", LINUX, None));
        assert!(!eval("'v3.12.15' === python_full_version", LINUX, None));
        // Extras are names, not versions, as uv compares them: `01` is not
        // the extra `1`, and a number past u64 is just a name.
        assert!(!eval("extra == '01'", LINUX, Some("1")));
        assert!(eval("extra != '01'", LINUX, Some("1")));
        assert!(eval("'1' == extra", LINUX, Some("1")));
        assert!(!eval("'01' == extra", LINUX, Some("1")));
        assert!(!eval("extra == '018446744073709551616'", LINUX, Some("1")));
        // Only `==` and `!=` compare extras: uv ignores every other
        // operator, `in` and `not in` included, and tog refuses them.
        for marker in [
            "extra < '1'".to_string(),
            "extra <= '1'".into(),
            "extra > '1'".into(),
            "extra >= '1'".into(),
            "extra ~= '1'".into(),
            "extra === '1'".into(),
            "extra in 'Foo_Bar'".into(),
            "extra not in 'Foo_Bar'".into(),
            "'foo' in extra".into(),
        ] {
            let op = if marker.contains("not in") {
                "not in"
            } else {
                marker.split(' ').nth(1).unwrap()
            };
            assert_eq!(
                marker_matches_for_extra(&marker, "3.12.14", LINUX, Some("foo-bar"))
                    .unwrap_err()
                    .to_string(),
                format!(
                    "unsupported environment marker `{marker}`: `{op}` cannot compare extra \
                     names; use `==` or `!=`"
                ),
            );
        }
        // `in` still compares strings for every other variable.
        assert!(eval("'linux' in sys_platform", LINUX, None));
        assert!(eval("sys_platform not in 'darwin win32'", LINUX, None));
    }
}

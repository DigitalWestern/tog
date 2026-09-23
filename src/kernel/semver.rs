//! npm semver: node-semver 7's version and range grammar, and its
//! `satisfies` without `includePrerelease`. Every npm range tog reads (pnpm
//! `patchedDependencies` keys, `engines.node`) goes through this one module.
//!
//! [`Range::parse`] accepts exactly what node-semver's `validRange` accepts
//! and refuses the rest, so a range tog cannot read is refused, never
//! guessed. The parsed [`Term`]s keep the partial versions as written, so a
//! caller that lowers ranges into its own request grammar (the toolchain
//! selector) can keep stricter rules of its own on top.
//!
//! Components past `Number.MAX_SAFE_INTEGER`, and any bound node-semver would
//! generate past it (the `2` in `^1`'s `<2.0.0-0`), are refused as node-semver
//! refuses them; every bump is checked arithmetic.

use std::cmp::Ordering;

/// The largest version component node-semver accepts (`Number.MAX_SAFE_INTEGER`).
pub const MAX_COMPONENT: u64 = 9_007_199_254_740_991;

/// node-semver's `MAX_LENGTH` for one version string. In a range it bounds
/// every comparator's version as node-semver renders it.
const MAX_LENGTH: usize = 256;

/// node-semver's regex caps (`MAX_SAFE_BUILD_LENGTH`, and `\d*` capped at
/// `MAX_LENGTH`): a build identifier, and whatever follows the first
/// non-digit of an alphanumeric prerelease identifier, is at most 250
/// characters, the digits before that non-digit at most 256, and a numeric
/// prerelease identifier at most 257 digits.
const MAX_IDENTIFIER: usize = MAX_LENGTH - 6;

/// A prerelease identifier, kept as written.
#[derive(Debug, Clone)]
pub enum Ident {
    Numeric(String),
    Alpha(String),
}

impl Ident {
    fn text(&self) -> &str {
        match self {
            Ident::Numeric(text) | Ident::Alpha(text) => text,
        }
    }
}

/// A numeric identifier as node-semver compares it: coerced to a JS Number,
/// so digits past `Number.MAX_SAFE_INTEGER` round (`9007199254740992` and
/// `9007199254740993` are equal). Rust's float parsing rounds to nearest
/// as JS does, and 257 digits stay far below overflow.
fn js_number(digits: &str) -> f64 {
    digits.parse().unwrap_or(f64::INFINITY)
}

impl PartialEq for Ident {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for Ident {}

impl Ord for Ident {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Ident::Numeric(a), Ident::Numeric(b)) => js_number(a).total_cmp(&js_number(b)),
            (Ident::Numeric(_), Ident::Alpha(_)) => Ordering::Less,
            (Ident::Alpha(_), Ident::Numeric(_)) => Ordering::Greater,
            (Ident::Alpha(a), Ident::Alpha(b)) => a.cmp(b),
        }
    }
}

impl PartialOrd for Ident {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// A full version. Build metadata is dropped, as it never affects precedence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemVer {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
    pub prerelease: Vec<Ident>,
}

impl SemVer {
    fn new(major: u64, minor: u64, patch: u64, prerelease: Vec<Ident>) -> SemVer {
        SemVer {
            major,
            minor,
            patch,
            prerelease,
        }
    }

    /// The `-0` node-semver puts on generated exclusive upper bounds, so
    /// that the next version's prereleases stay out.
    fn floor(major: u64, minor: u64, patch: u64) -> SemVer {
        SemVer::new(major, minor, patch, vec![Ident::Numeric("0".into())])
    }

    /// node-semver's `valid`: surrounding whitespace, an optional `v`, then
    /// `MAJOR.MINOR.PATCH[-prerelease][+build]`.
    pub fn parse(text: &str) -> Option<SemVer> {
        // node-semver measures before it trims.
        if text.len() > MAX_LENGTH {
            return None;
        }
        let text = text.trim();
        let partial = parse_partial(text.strip_prefix('v').unwrap_or(text))?;
        partial.full()
    }

    fn triple(&self) -> (u64, u64, u64) {
        (self.major, self.minor, self.patch)
    }
}

impl Ord for SemVer {
    fn cmp(&self, other: &Self) -> Ordering {
        self.triple().cmp(&other.triple()).then_with(|| {
            match (self.prerelease.is_empty(), other.prerelease.is_empty()) {
                (true, true) => Ordering::Equal,
                (true, false) => Ordering::Greater,
                (false, true) => Ordering::Less,
                (false, false) => self.prerelease.cmp(&other.prerelease),
            }
        })
    }
}

impl PartialOrd for SemVer {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// A version as a range writes it: up to three components, any of them
/// from some point on a wildcard (`x`, `X`, `*`) or missing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Partial {
    /// The numeric components before the first wildcard: `24.0.x` is
    /// `[24, 0]`, `*` is `[]`, `1.2.3` is `[1, 2, 3]`.
    pub parts: Vec<u64>,
    /// Only possible after three written components (`1.2.3-rc.1`,
    /// `1.2.x-rc.1`). node-semver drops it from a wildcard partial.
    pub prerelease: Vec<Ident>,
    /// Whether `+build` metadata was written. It never affects matching,
    /// and a range's builds are stripped before its terms are read (see
    /// [`Range::names_build`]), so a [`Term`]'s partial never has one.
    pub build: bool,
}

impl Partial {
    fn full(&self) -> Option<SemVer> {
        match self.parts[..] {
            [major, minor, patch] => {
                Some(SemVer::new(major, minor, patch, self.prerelease.clone()))
            }
            _ => None,
        }
    }
}

/// A range operator. `Eq` is both a bare version and `=`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Eq,
    Lt,
    Le,
    Gt,
    Ge,
    Caret,
    Tilde,
}

/// One term of a comparator set, as written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Term {
    Comparator {
        op: Op,
        version: Partial,
    },
    /// `low - high`, which node-semver only reads as a whole set.
    Hyphen {
        low: Partial,
        high: Partial,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Cmp {
    Lt,
    Le,
    Gt,
    Ge,
    Eq,
}

#[derive(Debug, Clone)]
struct Comparator {
    cmp: Cmp,
    version: SemVer,
}

impl Comparator {
    fn new(cmp: Cmp, version: SemVer) -> Comparator {
        Comparator { cmp, version }
    }

    fn test(&self, candidate: &SemVer) -> bool {
        let ordering = candidate.cmp(&self.version);
        match self.cmp {
            Cmp::Lt => ordering == Ordering::Less,
            Cmp::Le => ordering != Ordering::Greater,
            Cmp::Gt => ordering == Ordering::Greater,
            Cmp::Ge => ordering != Ordering::Less,
            Cmp::Eq => ordering == Ordering::Equal,
        }
    }
}

/// A parsed npm range: `||` alternatives of space-joined terms.
#[derive(Debug, Clone)]
pub struct Range {
    alternatives: Vec<Vec<Term>>,
    sets: Vec<Vec<Comparator>>,
    build: bool,
}

/// node-semver's `BUILDSTRIPRE`: every `+id(.id)*` (ids of letters, digits
/// and `-`, unbounded) is removed from the whole range before anything else
/// reads it. A `+` with no identifier after it stays, and is refused later.
fn strip_builds(text: &str) -> (String, bool) {
    let id_char = |byte: u8| byte.is_ascii_alphanumeric() || byte == b'-';
    let bytes = text.as_bytes();
    let mut kept = String::with_capacity(text.len());
    let mut stripped = false;
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'+' && bytes.get(index + 1).is_some_and(|byte| id_char(*byte)) {
            let mut end = index + 1;
            loop {
                while end < bytes.len() && id_char(bytes[end]) {
                    end += 1;
                }
                if bytes.get(end) == Some(&b'.')
                    && bytes.get(end + 1).is_some_and(|byte| id_char(*byte))
                {
                    end += 1;
                } else {
                    break;
                }
            }
            stripped = true;
            index = end;
        } else {
            let next = text[index..].chars().next().map_or(1, char::len_utf8);
            kept.push_str(&text[index..index + next]);
            index += next;
        }
    }
    (kept, stripped)
}

/// Why a range was refused. The caller names the field it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RangeError;

impl std::fmt::Display for RangeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("not a valid npm semver range")
    }
}

impl Range {
    pub fn parse(text: &str) -> Result<Range, RangeError> {
        let (text, build) = strip_builds(text);
        let mut alternatives = Vec::new();
        let mut sets = Vec::new();
        for alternative in text.split("||") {
            let terms = parse_set(alternative).ok_or(RangeError)?;
            let mut set = Vec::new();
            for term in &terms {
                set.extend(desugar(term).ok_or(RangeError)?);
            }
            alternatives.push(terms);
            sets.push(set);
        }
        Ok(Range {
            alternatives,
            sets,
            build,
        })
    }

    /// Whether the text carried `+build` metadata, which node-semver strips
    /// from a range before reading it (so it never reaches a [`Term`]).
    pub fn names_build(&self) -> bool {
        self.build
    }

    /// The terms as written, one list per `||` alternative. An empty list
    /// is an empty alternative, which admits every release.
    pub fn alternatives(&self) -> &[Vec<Term>] {
        &self.alternatives
    }

    /// node-semver's `satisfies` without `includePrerelease`: some
    /// alternative's comparators all admit the version, and a prerelease
    /// version is only admitted by an alternative that names a prerelease
    /// of the same `MAJOR.MINOR.PATCH`.
    pub fn satisfies(&self, candidate: &SemVer) -> bool {
        self.sets.iter().any(|set| {
            set.iter().all(|comparator| comparator.test(candidate))
                && (candidate.prerelease.is_empty()
                    || set.iter().any(|comparator| {
                        !comparator.version.prerelease.is_empty()
                            && comparator.version.triple() == candidate.triple()
                    }))
        })
    }

    /// [`Range::satisfies`] for version text; text that is not a version
    /// (a `file:` or git reference) satisfies nothing.
    pub fn satisfies_text(&self, candidate: &str) -> bool {
        SemVer::parse(candidate).is_some_and(|candidate| self.satisfies(&candidate))
    }
}

fn numeric(text: &str) -> Option<u64> {
    if text.is_empty()
        || !text.bytes().all(|byte| byte.is_ascii_digit())
        || (text.len() > 1 && text.starts_with('0'))
        || text.len() > 16
    {
        return None;
    }
    text.parse().ok().filter(|value| *value <= MAX_COMPONENT)
}

fn identifier_chars(text: &str) -> bool {
    !text.is_empty()
        && text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

/// `xr(.xr(.xr(-prerelease)?(+build)?)?)?` with no prefix.
fn parse_partial(text: &str) -> Option<Partial> {
    let (main, build) = match text.split_once('+') {
        Some((main, build)) => (main, Some(build)),
        None => (text, None),
    };
    let (core, prerelease) = match main.split_once('-') {
        Some((core, prerelease)) => (core, Some(prerelease)),
        None => (main, None),
    };
    let pieces = core.split('.').collect::<Vec<_>>();
    if pieces.len() > 3 || ((prerelease.is_some() || build.is_some()) && pieces.len() != 3) {
        return None;
    }
    let mut parts = Vec::new();
    let mut wildcard = false;
    for piece in pieces {
        if matches!(piece, "x" | "X" | "*") {
            wildcard = true;
        } else if wildcard {
            return None;
        } else {
            parts.push(numeric(piece)?);
        }
    }
    if let Some(build) = build {
        if !build
            .split('.')
            .all(|identifier| identifier_chars(identifier) && identifier.len() <= MAX_IDENTIFIER)
        {
            return None;
        }
    }
    let prerelease = match prerelease {
        None => Vec::new(),
        Some(prerelease) => prerelease
            .split('.')
            .map(|identifier| {
                let digits = identifier.bytes().take_while(u8::is_ascii_digit).count();
                if !identifier_chars(identifier) {
                    None
                } else if digits == identifier.len() {
                    ((identifier.len() == 1 || !identifier.starts_with('0'))
                        && identifier.len() <= MAX_LENGTH + 1)
                        .then(|| Ident::Numeric(identifier.to_string()))
                } else {
                    (digits <= MAX_LENGTH && identifier.len() - digits - 1 <= MAX_IDENTIFIER)
                        .then(|| Ident::Alpha(identifier.to_string()))
                }
            })
            .collect::<Option<Vec<_>>>()?,
    };
    Some(Partial {
        parts,
        prerelease,
        build: build.is_some(),
    })
}

/// A version token after its operator. Caret, tilde and any wildcard
/// partial take node-semver's `[v=]*` prefix; a full version under a
/// primitive operator takes only an optional `v`.
fn parse_version_token(op: Op, text: &str) -> Option<Partial> {
    let bare = text.trim_start_matches(['v', '=']);
    let partial = parse_partial(bare)?;
    let prefix = &text[..text.len() - bare.len()];
    let loose_prefix = matches!(op, Op::Caret | Op::Tilde) || partial.parts.len() < 3;
    (loose_prefix || prefix.is_empty() || prefix == "v").then_some(partial)
}

const OPERATORS: [(&str, Op); 8] = [
    ("~>", Op::Tilde),
    ("<=", Op::Le),
    (">=", Op::Ge),
    ("<", Op::Lt),
    (">", Op::Gt),
    ("=", Op::Eq),
    ("^", Op::Caret),
    ("~", Op::Tilde),
];

fn split_operator(token: &str) -> (Op, &str) {
    for (text, op) in OPERATORS {
        if let Some(rest) = token.strip_prefix(text) {
            return (op, rest);
        }
    }
    (Op::Eq, token)
}

/// The length of `MAJOR.MINOR.PATCH[-prerelease]` as node-semver renders a
/// full partial into a generated comparator (no prefix, no build).
fn rendered_len(partial: &Partial) -> usize {
    let core = partial
        .parts
        .iter()
        .map(|part| part.to_string().len() + 1)
        .sum::<usize>()
        - 1;
    let prerelease = partial
        .prerelease
        .iter()
        .map(|ident| ident.text().len() + 1)
        .sum::<usize>();
    core + prerelease
}

/// node-semver builds a `SemVer`, bounded by `MAX_LENGTH`, from every
/// comparator a full version produces. A primitive comparator and a hyphen
/// end without a prerelease keep the version as written (a `v` or `=`
/// prefix included, the build already stripped); caret, tilde and a
/// prerelease hyphen end re-render it.
fn fits(written: &str, partial: &Partial, rendered: bool) -> bool {
    partial.parts.len() < 3
        || if rendered {
            rendered_len(partial)
        } else {
            written.len()
        } <= MAX_LENGTH
}

fn parse_set(text: &str) -> Option<Vec<Term>> {
    let words = text.split_whitespace().collect::<Vec<_>>();
    if words.len() == 3 && words[1] == "-" {
        let low = parse_version_token(Op::Eq, words[0])?;
        let high = parse_version_token(Op::Eq, words[2])?;
        let high_rendered = !high.prerelease.is_empty();
        if !fits(words[0], &low, false) || !fits(words[2], &high, high_rendered) {
            return None;
        }
        return Some(vec![Term::Hyphen { low, high }]);
    }
    // An operator written apart from its version is one term (`>= 1.2`).
    let mut tokens = Vec::new();
    let mut words = words.into_iter();
    while let Some(word) = words.next() {
        if OPERATORS.iter().any(|(text, _)| *text == word) {
            tokens.push(format!("{word}{}", words.next()?));
        } else {
            tokens.push(word.to_string());
        }
    }
    tokens
        .iter()
        .map(|token| {
            let (op, rest) = split_operator(token);
            let version = parse_version_token(op, rest)?;
            fits(rest, &version, matches!(op, Op::Caret | Op::Tilde))
                .then_some(Term::Comparator { op, version })
        })
        .collect()
}

fn bump(value: u64) -> Option<u64> {
    value.checked_add(1).filter(|next| *next <= MAX_COMPONENT)
}

/// node-semver's desugaring (`replaceCaret`, `replaceTilde`,
/// `replaceXRange`, `hyphenReplace`) into primitive comparators. `None` is a
/// generated bound past the component limit.
fn desugar(term: &Term) -> Option<Vec<Comparator>> {
    let (op, version) = match term {
        Term::Hyphen { low, high } => {
            let mut set = Vec::new();
            match low.parts[..] {
                [] => {}
                [major] => set.push(Comparator::new(Cmp::Ge, SemVer::new(major, 0, 0, vec![]))),
                [major, minor] => set.push(Comparator::new(
                    Cmp::Ge,
                    SemVer::new(major, minor, 0, vec![]),
                )),
                _ => set.push(Comparator::new(Cmp::Ge, low.full()?)),
            }
            match high.parts[..] {
                [] => {}
                [major] => set.push(Comparator::new(Cmp::Lt, SemVer::floor(bump(major)?, 0, 0))),
                [major, minor] => set.push(Comparator::new(
                    Cmp::Lt,
                    SemVer::floor(major, bump(minor)?, 0),
                )),
                _ => set.push(Comparator::new(Cmp::Le, high.full()?)),
            }
            return Some(set);
        }
        Term::Comparator { op, version } => (*op, version),
    };
    let parts = &version.parts[..];
    let at_least = |major, minor, patch, prerelease| {
        Comparator::new(Cmp::Ge, SemVer::new(major, minor, patch, prerelease))
    };
    let below = |version: SemVer| Comparator::new(Cmp::Lt, version);
    Some(match op {
        Op::Caret => match *parts {
            [] => vec![],
            [major] => vec![
                at_least(major, 0, 0, vec![]),
                below(SemVer::floor(bump(major)?, 0, 0)),
            ],
            [0, minor] => vec![
                at_least(0, minor, 0, vec![]),
                below(SemVer::floor(0, bump(minor)?, 0)),
            ],
            [major, minor] => vec![
                at_least(major, minor, 0, vec![]),
                below(SemVer::floor(bump(major)?, 0, 0)),
            ],
            [0, 0, patch] => vec![
                at_least(0, 0, patch, version.prerelease.clone()),
                below(SemVer::floor(0, 0, bump(patch)?)),
            ],
            [0, minor, patch] => vec![
                at_least(0, minor, patch, version.prerelease.clone()),
                below(SemVer::floor(0, bump(minor)?, 0)),
            ],
            [major, minor, patch] => vec![
                at_least(major, minor, patch, version.prerelease.clone()),
                below(SemVer::floor(bump(major)?, 0, 0)),
            ],
            _ => return None,
        },
        Op::Tilde => match *parts {
            [] => vec![],
            [major] => vec![
                at_least(major, 0, 0, vec![]),
                below(SemVer::floor(bump(major)?, 0, 0)),
            ],
            [major, minor] => vec![
                at_least(major, minor, 0, vec![]),
                below(SemVer::floor(major, bump(minor)?, 0)),
            ],
            [major, minor, patch] => vec![
                at_least(major, minor, patch, version.prerelease.clone()),
                below(SemVer::floor(major, bump(minor)?, 0)),
            ],
            _ => return None,
        },
        _ if parts.len() == 3 => {
            let cmp = match op {
                Op::Lt => Cmp::Lt,
                Op::Le => Cmp::Le,
                Op::Gt => Cmp::Gt,
                Op::Ge => Cmp::Ge,
                _ => Cmp::Eq,
            };
            vec![Comparator::new(cmp, version.full()?)]
        }
        // Wildcard partials (`replaceXRange`); any prerelease is dropped.
        _ => {
            let (major, minor) = (parts.first().copied(), parts.get(1).copied());
            let Some(major) = major else {
                // `>*` and `<*` admit nothing; every other `*` admits all.
                return Some(match op {
                    Op::Gt | Op::Lt => vec![below(SemVer::floor(0, 0, 0))],
                    _ => vec![],
                });
            };
            // The first version past everything the partial spells.
            let next = || match minor {
                None => Some(SemVer::new(bump(major)?, 0, 0, vec![])),
                Some(minor) => Some(SemVer::new(major, bump(minor)?, 0, vec![])),
            };
            let low = SemVer::new(major, minor.unwrap_or(0), 0, vec![]);
            match op {
                Op::Gt => vec![Comparator::new(Cmp::Ge, next()?)],
                Op::Ge => vec![Comparator::new(Cmp::Ge, low)],
                Op::Lt => vec![below(SemVer::floor(major, minor.unwrap_or(0), 0))],
                Op::Le => {
                    let next = next()?;
                    vec![below(SemVer::floor(next.major, next.minor, 0))]
                }
                _ => {
                    let next = next()?;
                    vec![
                        Comparator::new(Cmp::Ge, low),
                        below(SemVer::floor(next.major, next.minor, 0)),
                    ]
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Generated with node-semver 7.8.5 (the copy npm 11 bundles):
    /// `range<TAB>version<TAB>satisfies`, or `range<TAB>-<TAB>invalid` for a
    /// range `validRange` refuses.
    const CASES: &str = include_str!("semver_cases.tsv");

    #[test]
    fn ranges_agree_with_node_semver_case_by_case() {
        let mut checked = 0;
        for line in CASES
            .lines()
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
        {
            let fields = line.split('\t').collect::<Vec<_>>();
            let [range, version, expected] = fields[..] else {
                panic!("malformed case line {line:?}");
            };
            let parsed = Range::parse(range);
            if expected == "invalid" {
                assert!(parsed.is_err(), "{range:?} should be refused");
            } else {
                let parsed = parsed.unwrap_or_else(|_| panic!("{range:?} should parse"));
                assert_eq!(
                    parsed.satisfies_text(version),
                    expected == "true",
                    "{range:?} vs {version:?}"
                );
            }
            checked += 1;
        }
        assert!(checked > 200, "only {checked} cases");
    }

    #[test]
    fn versions_parse_like_node_semver_valid() {
        for (text, valid) in [
            ("1.2.3", true),
            (" v1.2.3 ", true),
            ("1.2.3-rc.1+build.5", true),
            ("=1.2.3", false),
            ("1.2", false),
            ("01.2.3", false),
            ("1.2.3-01", false),
            ("1.2.3-a..b", false),
            ("9007199254740991.0.0", true),
            ("9007199254740992.0.0", false),
            ("18446744073709551616.0.0", false),
        ] {
            assert_eq!(SemVer::parse(text).is_some(), valid, "{text:?}");
        }
        let order = [
            "1.0.0-0",
            "1.0.0-2",
            "1.0.0-10",
            "1.0.0-99999999999999999999",
            "1.0.0-alpha",
            "1.0.0-alpha.1",
            "1.0.0-alpha.beta",
            "1.0.0-beta",
            "1.0.0",
            "1.0.1",
        ];
        for pair in order.windows(2) {
            assert!(
                SemVer::parse(pair[0]).unwrap() < SemVer::parse(pair[1]).unwrap(),
                "{} < {}",
                pair[0],
                pair[1]
            );
        }
    }
}

//! A small, dependency-free PEP 440 parser and specifier evaluator.
//!
//! This is shared by interpreter selection, lock-file package selection, and
//! PEP 508 marker evaluation.  Keeping the version ordering here is
//! important: Python versions are also package versions as far as a marker or
//! a lock constraint is concerned.

use std::cmp::Ordering;
use std::io;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Version {
    raw: String,
    epoch: u64,
    release: Vec<u64>,
    release_len: usize,
    pre: Option<(PreKind, u64)>,
    post: Option<u64>,
    dev: Option<u64>,
    local: Option<Vec<LocalPart>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
enum PreKind {
    Alpha,
    Beta,
    ReleaseCandidate,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum LocalPart {
    Numeric(u64),
    Alpha(String),
}

impl Version {
    pub fn parse(text: &str) -> Result<Self, String> {
        let raw = text.trim();
        if raw.is_empty() {
            return Err("version is empty".into());
        }
        let mut public = raw.to_ascii_lowercase();
        if let Some(stripped) = public.strip_prefix('v') {
            public = stripped.to_string();
        }

        let local = if let Some((_, local_part)) = public.split_once('+') {
            if local_part.is_empty() || local_part.contains('+') {
                return Err("invalid local version".into());
            }
            Some(parse_local(local_part)?)
        } else {
            None
        };
        let public = public.split('+').next().unwrap_or(&public);

        let (epoch, public) = if let Some((epoch, rest)) = public.split_once('!') {
            if epoch.is_empty() || !epoch.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err("invalid epoch".into());
            }
            (parse_number(epoch)?, rest)
        } else {
            (0, public)
        };

        let release_end = public
            .char_indices()
            .find(|(_, byte)| !byte.is_ascii_digit() && *byte != '.')
            .map(|(index, _)| index)
            .unwrap_or(public.len());
        let mut release_text = &public[..release_end];
        while release_text.ends_with('.') {
            release_text = &release_text[..release_text.len() - 1];
        }
        if release_text.is_empty() {
            return Err("release segment is missing".into());
        }
        let release_parts: Vec<_> = release_text.split('.').collect();
        if release_parts.iter().any(|part| part.is_empty()) {
            return Err("release segments must be numeric".into());
        }
        let mut release = Vec::with_capacity(release_parts.len());
        for part in &release_parts {
            if !part.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err("release segments must be numeric".into());
            }
            release.push(parse_number(part)?);
        }

        let suffix = public[release_end..]
            .trim_start_matches(['.', '-', '_'])
            .replace(['-', '_'], ".");
        let (pre, post, dev) = parse_suffix(&suffix)?;
        Ok(Self {
            raw: raw.to_string(),
            epoch,
            release_len: release.len(),
            release,
            pre,
            post,
            dev,
            local,
        })
    }

    pub fn raw(&self) -> &str {
        &self.raw
    }

    pub fn release(&self) -> &[u64] {
        &self.release
    }

    pub fn release_len(&self) -> usize {
        self.release_len
    }

    pub fn major(&self) -> u64 {
        self.release.first().copied().unwrap_or(0)
    }

    pub fn minor(&self) -> u64 {
        self.release.get(1).copied().unwrap_or(0)
    }

    pub fn patch(&self) -> u64 {
        self.release.get(2).copied().unwrap_or(0)
    }

    pub fn is_prerelease(&self) -> bool {
        self.pre.is_some() || self.dev.is_some()
    }

    pub fn has_epoch(&self) -> bool {
        self.epoch != 0
    }

    pub fn has_local(&self) -> bool {
        self.local.is_some()
    }

    fn from_release_with_epoch(release: Vec<u64>, epoch: u64) -> Self {
        let release_len = release.len();
        Self {
            raw: release
                .iter()
                .map(u64::to_string)
                .collect::<Vec<_>>()
                .join("."),
            epoch,
            release,
            release_len,
            pre: None,
            post: None,
            dev: None,
            local: None,
        }
    }

    fn same_public(&self, other: &Self) -> bool {
        self.epoch == other.epoch
            && self.release_cmp(other) == Ordering::Equal
            && self.pre == other.pre
            && self.post == other.post
            && self.dev == other.dev
    }

    fn same_release(&self, other: &Self) -> bool {
        self.epoch == other.epoch && self.release_cmp(other) == Ordering::Equal
    }

    fn release_cmp(&self, other: &Self) -> Ordering {
        compare_release(&self.release, &other.release)
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        self.epoch
            .cmp(&other.epoch)
            .then_with(|| compare_release(&self.release, &other.release))
            .then_with(|| compare_pre(self, other))
            .then_with(|| compare_optional_number(self.post, other.post, false))
            .then_with(|| compare_optional_number(self.dev, other.dev, true))
            .then_with(|| compare_local(self.local.as_deref(), other.local.as_deref()))
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

fn compare_release(left: &[u64], right: &[u64]) -> Ordering {
    let length = left.len().max(right.len());
    for index in 0..length {
        let ordering = left
            .get(index)
            .copied()
            .unwrap_or(0)
            .cmp(&right.get(index).copied().unwrap_or(0));
        if ordering != Ordering::Equal {
            return ordering;
        }
    }
    Ordering::Equal
}

fn compare_pre(left: &Version, right: &Version) -> Ordering {
    // PEP 440 orders a dev-only release before pre-releases, while a release
    // with no pre-release segment is later than all pre-releases.
    let rank = |version: &Version| {
        if version.pre.is_some() {
            0
        } else if version.post.is_none() && version.dev.is_some() {
            -1
        } else {
            1
        }
    };
    let ordering = rank(left).cmp(&rank(right));
    if ordering != Ordering::Equal {
        return ordering;
    }
    left.pre.cmp(&right.pre)
}

fn compare_optional_number(
    left: Option<u64>,
    right: Option<u64>,
    missing_is_high: bool,
) -> Ordering {
    match (left, right) {
        (Some(left), Some(right)) => left.cmp(&right),
        (None, None) => Ordering::Equal,
        (None, Some(_)) => {
            if missing_is_high {
                Ordering::Greater
            } else {
                Ordering::Less
            }
        }
        (Some(_), None) => {
            if missing_is_high {
                Ordering::Less
            } else {
                Ordering::Greater
            }
        }
    }
}

fn compare_local(left: Option<&[LocalPart]>, right: Option<&[LocalPart]>) -> Ordering {
    let (Some(left), Some(right)) = (left, right) else {
        return match (left, right) {
            (None, None) => Ordering::Equal,
            (None, Some(_)) => Ordering::Less,
            (Some(_), None) => Ordering::Greater,
            (Some(_), Some(_)) => Ordering::Equal,
        };
    };
    for (left, right) in left.iter().zip(right) {
        let ordering = match (left, right) {
            (LocalPart::Numeric(left), LocalPart::Numeric(right)) => left.cmp(right),
            (LocalPart::Alpha(left), LocalPart::Alpha(right)) => left.cmp(right),
            (LocalPart::Numeric(_), LocalPart::Alpha(_)) => Ordering::Greater,
            (LocalPart::Alpha(_), LocalPart::Numeric(_)) => Ordering::Less,
        };
        if ordering != Ordering::Equal {
            return ordering;
        }
    }
    left.len().cmp(&right.len())
}

fn parse_number(text: &str) -> Result<u64, String> {
    text.parse::<u64>()
        .map_err(|_| "numeric version segment is too large".into())
}

fn parse_local(text: &str) -> Result<Vec<LocalPart>, String> {
    text.split(['.', '-', '_'])
        .map(|part| {
            if part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
                return Err("invalid local version segment".into());
            }
            if part.bytes().all(|byte| byte.is_ascii_digit()) {
                Ok(LocalPart::Numeric(parse_number(part)?))
            } else {
                Ok(LocalPart::Alpha(part.to_ascii_lowercase()))
            }
        })
        .collect()
}

fn parse_suffix(
    suffix: &str,
) -> Result<(Option<(PreKind, u64)>, Option<u64>, Option<u64>), String> {
    if suffix.is_empty() {
        return Ok((None, None, None));
    }
    let mut pre = None;
    let mut post = None;
    let mut dev = None;
    let mut rest = suffix.trim_matches('.');
    while !rest.is_empty() {
        rest = rest.trim_start_matches('.');
        if rest.is_empty() {
            break;
        }
        let (kind, consumed) = if let Some(consumed) = rest.strip_prefix("alpha") {
            (Some(PreKind::Alpha), rest.len() - consumed.len())
        } else if let Some(consumed) = rest.strip_prefix("a") {
            (Some(PreKind::Alpha), rest.len() - consumed.len())
        } else if let Some(consumed) = rest.strip_prefix("beta") {
            (Some(PreKind::Beta), rest.len() - consumed.len())
        } else if let Some(consumed) = rest.strip_prefix("b") {
            (Some(PreKind::Beta), rest.len() - consumed.len())
        } else if let Some(consumed) = rest.strip_prefix("preview") {
            (Some(PreKind::ReleaseCandidate), rest.len() - consumed.len())
        } else if let Some(consumed) = rest.strip_prefix("pre") {
            (Some(PreKind::ReleaseCandidate), rest.len() - consumed.len())
        } else if let Some(consumed) = rest.strip_prefix("rc") {
            (Some(PreKind::ReleaseCandidate), rest.len() - consumed.len())
        } else if let Some(consumed) = rest.strip_prefix("c") {
            (Some(PreKind::ReleaseCandidate), rest.len() - consumed.len())
        } else {
            (None, 0)
        };
        if let Some(kind) = kind {
            let after = rest[consumed..].trim_start_matches('.');
            let digits = after.chars().take_while(char::is_ascii_digit).count();
            let number = if digits == 0 {
                0
            } else {
                parse_number(&after[..digits])?
            };
            if pre.replace((kind, number)).is_some() {
                return Err("duplicate pre-release segment".into());
            }
            rest = &after[digits..];
            continue;
        }

        let (is_post, consumed) = if let Some(after) = rest.strip_prefix("post") {
            (true, rest.len() - after.len())
        } else if let Some(after) = rest.strip_prefix("rev") {
            (true, rest.len() - after.len())
        } else if let Some(after) = rest.strip_prefix("r") {
            (true, rest.len() - after.len())
        } else if rest
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_digit())
        {
            (true, 0)
        } else {
            (false, 0)
        };
        if is_post {
            let after = rest[consumed..].trim_start_matches('.');
            let digits = after.chars().take_while(char::is_ascii_digit).count();
            let number = if digits == 0 {
                0
            } else {
                parse_number(&after[..digits])?
            };
            if post.replace(number).is_some() {
                return Err("duplicate post-release segment".into());
            }
            rest = &after[digits..];
            continue;
        }
        if let Some(after) = rest.strip_prefix("dev") {
            let after = after.trim_start_matches('.');
            let digits = after.chars().take_while(char::is_ascii_digit).count();
            let number = if digits == 0 {
                0
            } else {
                parse_number(&after[..digits])?
            };
            if dev.replace(number).is_some() {
                return Err("duplicate dev-release segment".into());
            }
            rest = &after[digits..];
            continue;
        }
        return Err(format!("unrecognized version suffix `{rest}`"));
    }
    Ok((pre, post, dev))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Operator {
    GreaterEqual,
    Greater,
    LessEqual,
    Less,
    Equal,
    NotEqual,
    Compatible,
    PoetryCaret,
    PoetryTilde,
    ArbitraryEqual,
    BareEqual,
}

#[derive(Clone, Debug)]
enum Clause {
    Any,
    Literal(String),
    Compare(Operator, Version),
    PrefixEqual { epoch: u64, prefix: Vec<u64> },
    PrefixNotEqual { epoch: u64, prefix: Vec<u64> },
}

#[derive(Clone, Debug)]
pub struct SpecifierSet {
    alternatives: Vec<Vec<Clause>>,
}

impl SpecifierSet {
    pub fn parse(text: &str, source: &str) -> io::Result<Self> {
        if text.trim().is_empty() {
            return Ok(Self {
                alternatives: vec![vec![Clause::Any]],
            });
        }
        let alternatives = text
            .split("||")
            .map(|alternative| parse_alternative(alternative, text, source))
            .collect::<io::Result<Vec<_>>>()?;
        if alternatives.is_empty() {
            return invalid_specifier(source, text, "empty expression");
        }
        Ok(Self { alternatives })
    }

    pub fn matches(&self, version: &Version) -> bool {
        if version.is_prerelease() && !self.allows_prereleases() {
            return false;
        }
        self.matches_raw(version)
    }

    /// PEP 440 allows a pre-release as a fallback when a set has no matching
    /// final release. Callers that have a candidate set can use this method to
    /// implement that final fallback without weakening ordinary comparisons.
    pub fn matches_with_fallback(&self, version: &Version, candidates: &[Version]) -> bool {
        if !version.is_prerelease() || self.allows_prereleases() {
            return self.matches_raw(version);
        }
        if candidates
            .iter()
            .any(|candidate| !candidate.is_prerelease() && self.matches_raw(candidate))
        {
            return false;
        }
        self.matches_raw(version)
    }

    fn matches_raw(&self, version: &Version) -> bool {
        self.alternatives
            .iter()
            .any(|clauses| clauses.iter().all(|clause| clause_matches(clause, version)))
    }

    fn allows_prereleases(&self) -> bool {
        self.alternatives
            .iter()
            .flatten()
            .any(|clause| match clause {
                Clause::Compare(_, target) => target.is_prerelease(),
                _ => false,
            })
    }
}

fn invalid_specifier<T>(source: &str, text: &str, why: &str) -> io::Result<T> {
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        format!("{source}: invalid PEP 440 specifier `{text}`: {why}"),
    ))
}

fn parse_alternative(alternative: &str, full_text: &str, source: &str) -> io::Result<Vec<Clause>> {
    let mut clauses = Vec::new();
    let bytes = alternative.as_bytes();
    let mut pos = 0;
    let mut saw_token = false;
    let mut after_comma = false;
    while pos < bytes.len() {
        while pos < bytes.len() && bytes[pos].is_ascii_whitespace() {
            pos += 1;
        }
        if pos == bytes.len() {
            if after_comma {
                return invalid_specifier(source, full_text, "trailing comma");
            }
            break;
        }
        if bytes[pos] == b',' {
            if after_comma || !saw_token {
                return invalid_specifier(source, full_text, "empty comma-separated clause");
            }
            after_comma = true;
            pos += 1;
            continue;
        }
        after_comma = false;
        let (operator, consumed) = parse_operator(&alternative[pos..]);
        let Some(operator) = operator else {
            return invalid_specifier(source, full_text, "expected a supported operator");
        };
        pos += consumed;
        while pos < bytes.len() && bytes[pos].is_ascii_whitespace() {
            pos += 1;
        }
        let start = pos;
        while pos < bytes.len() && !bytes[pos].is_ascii_whitespace() && bytes[pos] != b',' {
            pos += 1;
        }
        if start == pos {
            return invalid_specifier(source, full_text, "operator has no version");
        }
        clauses.extend(expand_clause(
            operator,
            &alternative[start..pos],
            full_text,
            source,
        )?);
        saw_token = true;
    }
    if !saw_token {
        return invalid_specifier(source, full_text, "empty expression");
    }
    Ok(clauses)
}

fn parse_operator(text: &str) -> (Option<Operator>, usize) {
    for (operator, spelling) in [
        (Operator::ArbitraryEqual, "==="),
        (Operator::GreaterEqual, ">="),
        (Operator::LessEqual, "<="),
        (Operator::NotEqual, "!="),
        (Operator::Compatible, "~="),
        (Operator::Equal, "=="),
        (Operator::Greater, ">"),
        (Operator::Less, "<"),
        (Operator::PoetryCaret, "^"),
        (Operator::PoetryTilde, "~"),
    ] {
        if text.starts_with(spelling) {
            return (Some(operator), spelling.len());
        }
    }
    if !text.is_empty() && !text.starts_with(',') && !text.starts_with('|') {
        return (Some(Operator::BareEqual), 0);
    }
    (None, 0)
}

fn expand_clause(
    operator: Operator,
    version_text: &str,
    full_text: &str,
    source: &str,
) -> io::Result<Vec<Clause>> {
    if matches!(operator, Operator::ArbitraryEqual) {
        return Ok(vec![Clause::Literal(version_text.to_string())]);
    }
    if version_text == "*" {
        return match operator {
            Operator::Equal | Operator::BareEqual => Ok(vec![Clause::Any]),
            _ => invalid_specifier(source, full_text, "wildcard is only valid with equality"),
        };
    }
    let wildcard = version_text.ends_with(".*");
    let version_text = if wildcard {
        &version_text[..version_text.len() - 2]
    } else {
        version_text
    };
    let version = Version::parse(version_text).map_err(|why| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{source}: invalid PEP 440 specifier `{full_text}`: {why}"),
        )
    })?;
    if wildcard {
        if version.pre.is_some()
            || version.post.is_some()
            || version.dev.is_some()
            || version.local.is_some()
        {
            return invalid_specifier(
                source,
                full_text,
                "wildcards may only follow a release prefix",
            );
        }
        let prefix = version.release[..version.release_len].to_vec();
        return match operator {
            Operator::Equal | Operator::BareEqual => Ok(vec![Clause::PrefixEqual {
                epoch: version.epoch,
                prefix,
            }]),
            Operator::NotEqual => Ok(vec![Clause::PrefixNotEqual {
                epoch: version.epoch,
                prefix,
            }]),
            _ => invalid_specifier(source, full_text, "wildcards need == or !="),
        };
    }
    if matches!(operator, Operator::Equal | Operator::NotEqual) {
        return Ok(vec![Clause::Compare(operator, version)]);
    }
    if version.has_local() {
        return invalid_specifier(
            source,
            full_text,
            "local versions are only valid with equality",
        );
    }
    if operator == Operator::BareEqual
        && version.release_len < 3
        && version.pre.is_none()
        && version.post.is_none()
        && version.dev.is_none()
    {
        return Ok(vec![Clause::PrefixEqual {
            epoch: version.epoch,
            prefix: version.release[..version.release_len].to_vec(),
        }]);
    }
    match operator {
        Operator::BareEqual => Ok(vec![Clause::Compare(Operator::Equal, version)]),
        Operator::Compatible => {
            if version.release_len < 2 {
                return invalid_specifier(
                    source,
                    full_text,
                    "~= needs at least two release segments",
                );
            }
            let upper = compatible_upper(&version);
            Ok(vec![
                Clause::Compare(Operator::GreaterEqual, version),
                Clause::PrefixEqual {
                    epoch: upper.1.epoch,
                    prefix: upper.0,
                },
                Clause::Compare(Operator::Less, upper.1),
            ])
        }
        Operator::PoetryCaret => {
            let mut release = version.release.clone();
            let index = release
                .iter()
                .position(|value| *value != 0)
                .unwrap_or(release.len().saturating_sub(1));
            release[index] = release[index].checked_add(1).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "version is too large")
            })?;
            release.truncate(index + 1);
            let epoch = version.epoch;
            Ok(vec![
                Clause::Compare(Operator::GreaterEqual, version),
                Clause::Compare(
                    Operator::Less,
                    Version::from_release_with_epoch(release, epoch),
                ),
            ])
        }
        Operator::PoetryTilde => {
            let mut release = version.release.clone();
            let index = if release.len() == 1 { 0 } else { 1 };
            release[index] = release[index].checked_add(1).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "version is too large")
            })?;
            release.truncate(index + 1);
            let epoch = version.epoch;
            Ok(vec![
                Clause::Compare(Operator::GreaterEqual, version),
                Clause::Compare(
                    Operator::Less,
                    Version::from_release_with_epoch(release, epoch),
                ),
            ])
        }
        _ => Ok(vec![Clause::Compare(operator, version)]),
    }
}

fn compatible_upper(version: &Version) -> (Vec<u64>, Version) {
    let prefix_len = version.release_len.saturating_sub(1).max(1);
    let prefix = version.release[..prefix_len].to_vec();
    let mut upper = prefix.clone();
    let index = upper.len() - 1;
    upper[index] += 1;
    (
        prefix,
        Version::from_release_with_epoch(upper, version.epoch),
    )
}

fn clause_matches(clause: &Clause, version: &Version) -> bool {
    match clause {
        Clause::Any => true,
        Clause::Literal(text) => version.raw() == text,
        Clause::PrefixEqual { epoch, prefix } => {
            version.epoch == *epoch
                && prefix.iter().enumerate().all(|(index, value)| {
                    version.release().get(index).copied().unwrap_or(0) == *value
                })
        }
        Clause::PrefixNotEqual { epoch, prefix } => {
            version.epoch != *epoch
                || prefix.iter().enumerate().any(|(index, value)| {
                    version.release().get(index).copied().unwrap_or(0) != *value
                })
        }
        Clause::Compare(operator, target) => match operator {
            Operator::Equal => {
                if target.has_local() {
                    version.same_public(target) && version.local == target.local
                } else {
                    version.same_public(target)
                }
            }
            Operator::NotEqual => {
                if target.has_local() {
                    !(version.same_public(target) && version.local == target.local)
                } else {
                    !version.same_public(target)
                }
            }
            Operator::GreaterEqual => compare_public(version, target) != Ordering::Less,
            Operator::Greater => exclusive_greater(version, target),
            Operator::LessEqual => compare_public(version, target) != Ordering::Greater,
            Operator::Less => exclusive_less(version, target),
            Operator::ArbitraryEqual
            | Operator::Compatible
            | Operator::PoetryCaret
            | Operator::PoetryTilde
            | Operator::BareEqual => false,
        },
    }
}

/// Ordered specifiers ignore candidate local labels, but `>` and `<` have
/// additional PEP 440 exclusions for versions sharing the target's release.
/// Keep this separate from `Ord`: local versions still participate in the
/// global version ordering used when choosing the newest lock candidate.
fn compare_public(left: &Version, right: &Version) -> Ordering {
    left.epoch
        .cmp(&right.epoch)
        .then_with(|| left.release_cmp(right))
        .then_with(|| compare_pre(left, right))
        .then_with(|| compare_optional_number(left.post, right.post, false))
        .then_with(|| compare_optional_number(left.dev, right.dev, true))
}

fn exclusive_greater(candidate: &Version, target: &Version) -> bool {
    if compare_public(candidate, target) != Ordering::Greater {
        return false;
    }
    // `>V` does not admit a post-release of V unless V is itself a
    // post-release. This compares the base release, so 1.0.0.post1 is also a
    // post-release of 1.0 for this purpose.
    if target.post.is_none() && candidate.post.is_some() && candidate.same_release(target) {
        return false;
    }
    // A local version of the target's base release is not admitted by `>V`.
    if candidate.local.is_some() && candidate.same_release(target) {
        return false;
    }
    true
}

fn exclusive_less(candidate: &Version, target: &Version) -> bool {
    if compare_public(candidate, target) != Ordering::Less {
        return false;
    }
    // `<V` does not admit a pre-release of V unless V is itself a
    // pre-release. Development releases are pre-releases for this rule.
    if !target.is_prerelease() && candidate.is_prerelease() && candidate.same_release(target) {
        return false;
    }
    true
}

/// Match a PEP 440 specifier against a complete version. The same function is
/// used for pinned Python and for versions read from package lock files.
pub fn matches_specifier(specifier: &str, version: &str) -> io::Result<bool> {
    let candidate = Version::parse(version).map_err(|why| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("specifier: invalid PEP 440 version `{version}`: {why}"),
        )
    })?;
    Ok(SpecifierSet::parse(specifier, "specifier")?.matches(&candidate))
}

/// Match an intersected set of specifiers against one candidate, applying
/// PEP 440's pre-release fallback when the supplied candidate set has no
/// matching final release.
pub fn matches_specifiers_with_candidates(
    specifiers: &[&str],
    version: &str,
    candidates: &[&str],
) -> io::Result<bool> {
    let sets = specifiers
        .iter()
        .map(|specifier| SpecifierSet::parse(specifier, "specifier"))
        .collect::<io::Result<Vec<_>>>()?;
    let candidate = Version::parse(version).map_err(|why| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("specifier: invalid PEP 440 version `{version}`: {why}"),
        )
    })?;
    let parsed_candidates = candidates
        .iter()
        .map(|candidate| {
            Version::parse(candidate).map_err(|why| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("specifier: invalid PEP 440 version `{candidate}`: {why}"),
                )
            })
        })
        .collect::<io::Result<Vec<_>>>()?;
    let raw_matches = sets.iter().all(|set| set.matches_raw(&candidate));
    if !raw_matches {
        return Ok(false);
    }
    if candidate.is_prerelease()
        && !sets.iter().any(SpecifierSet::allows_prereleases)
        && parsed_candidates
            .iter()
            .any(|other| !other.is_prerelease() && sets.iter().all(|set| set.matches_raw(other)))
    {
        return Ok(false);
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packaging_ordering_examples() {
        let ordered = [
            "1.dev0",
            "1.0.dev456",
            "1.0a1",
            "1.0a2.dev456",
            "1.0a12.dev456",
            "1.0a12",
            "1.0b1.dev456",
            "1.0b2",
            "1.0b2.post345.dev456",
            "1.0b2.post345",
            "1.0rc1.dev456",
            "1.0rc1",
            "1.0",
            "1.0+abc.5",
            "1.0+abc.7",
            "1.0+5",
            "1.0.post456.dev34",
            "1.0.post456",
            "1.0.15",
            "1.1.dev1",
            "2!1.0",
        ];
        for pair in ordered.windows(2) {
            assert!(
                Version::parse(pair[0]).unwrap() < Version::parse(pair[1]).unwrap(),
                "{} < {}",
                pair[0],
                pair[1]
            );
        }
        assert!(matches_specifier(">=1", "1.0.0.post1").unwrap());
        assert!(!matches_specifier(">=1.0.0", "1.0.0-beta").unwrap());
        assert!(matches_specifier(">=1.0.0b0", "1.0.0-beta").unwrap());
        assert!(matches_specifiers_with_candidates(&[">=1"], "2.0rc1", &["2.0rc1"]).unwrap());
        assert!(
            !matches_specifiers_with_candidates(&[">=1"], "2.0rc1", &["2.0rc1", "2.0"]).unwrap()
        );
        assert!(matches_specifier("~=1.4.5", "1.4.9").unwrap());
        assert!(!matches_specifier("~=1.4.5", "1.5.0").unwrap());
        assert!(matches_specifier("==1.0.*", "1.0.post1").unwrap());
        assert!(matches_specifier("==1!1.0.*", "1!1.0.1").unwrap());
        assert!(!matches_specifier("==1!1.0.*", "1.0.1").unwrap());
        assert!(matches_specifier("==1.0.post2", "1.0.post-2").unwrap());
        assert!(matches_specifier("==1.0a1", "1.0.a.1").unwrap());
        assert!(matches_specifier("==1.0.dev1", "1.0.dev.1").unwrap());
        assert!(matches_specifier("~=1.4", "1.9").unwrap());
        assert!(matches_specifier("~=1.4.5", "1.4.9").unwrap());
        assert!(SpecifierSet::parse("~=1", "test").is_err());
        assert!(matches_specifier("==1.0", "1.0+local").unwrap());
        assert!(!matches_specifier("==1.0+other", "1.0+local").unwrap());
        assert!(matches_specifier("==1!1.0", "1!1.0.0").unwrap());
    }

    #[test]
    fn exclusive_ordered_comparisons_apply_pep440_exclusions() {
        let cases = [
            (">1.7", "1.7.1", true),
            (">1.7", "1.7.0.post1", false),
            (">1.7", "1.7+local", false),
            (">1.7.post2", "1.7.1", true),
            (">1.7.post2", "1.7.0.post3", true),
            (">1.7.post2", "1.7.0", false),
            (">1.7.post2", "1.7.0.post3+local", false),
            ("<1.0", "1.0rc1", false),
            ("<1.0", "1.0.dev1", false),
            ("<1.0", "0.9", true),
            ("<1.0rc2", "1.0rc1", true),
        ];
        for (specifier, version, expected) in cases {
            assert_eq!(
                matches_specifier(specifier, version).unwrap(),
                expected,
                "{specifier} / {version}"
            );
        }
        assert!(!matches_specifiers_with_candidates(&["<1.0"], "1.0rc1", &["1.0rc1"]).unwrap());
    }

    #[test]
    fn pre_release_spellings_normalize_to_pep440_phases() {
        let cases = [
            ("1.0alpha1", "1.0a1"),
            ("1.0a1", "1.0a1"),
            ("1.0beta1", "1.0b1"),
            ("1.0b1", "1.0b1"),
            ("1.0c1", "1.0rc1"),
            ("1.0rc1", "1.0rc1"),
            ("1.0pre1", "1.0rc1"),
            ("1.0preview1", "1.0rc1"),
        ];
        for (spelling, canonical) in cases {
            let spelling = Version::parse(spelling).unwrap();
            let canonical = Version::parse(canonical).unwrap();
            assert!(
                spelling.same_public(&canonical),
                "{spelling:?} / {canonical:?}"
            );
        }
        assert!(!matches_specifier("<=1.0b1", "1.0preview1").unwrap());
    }
}

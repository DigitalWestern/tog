//! A small, dependency-free PEP 440 parser and specifier evaluator.
//!
//! This is shared by interpreter selection, lock-file package selection, and
//! PEP 508 marker evaluation.  Keeping the version ordering here is
//! important: Python versions are also package versions as far as a marker or
//! a lock constraint is concerned.

use std::cmp::Ordering;
use std::io;

/// Equality is PEP 440's, the same answer `Ord` gives: `1.0 == 1.0.0` and
/// `1.0A1 == 1.0a1`. The spelling in `raw` is not part of it.
#[derive(Clone, Debug)]
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

        // Release: N(.N)*. A dot not followed by a digit belongs to the
        // suffix (`1.0.a1`), where the suffix grammar decides whether it is
        // a valid separator.
        let bytes = public.as_bytes();
        let mut release_end = 0;
        while release_end < bytes.len() && bytes[release_end].is_ascii_digit() {
            release_end += 1;
        }
        if release_end == 0 {
            return Err("release segment is missing".into());
        }
        while release_end + 1 < bytes.len()
            && bytes[release_end] == b'.'
            && bytes[release_end + 1].is_ascii_digit()
        {
            release_end += 1;
            while release_end < bytes.len() && bytes[release_end].is_ascii_digit() {
                release_end += 1;
            }
        }
        let mut release = Vec::new();
        for part in public[..release_end].split('.') {
            release.push(parse_number(part)?);
        }
        let (pre, post, dev) = parse_suffix(&public[release_end..])?;
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

    /// The normalized spelling, as `packaging` prints it: `V1.0-RC1` is
    /// `1.0rc1`, `1.0-1` is `1.0.post1`. Release segments keep their count.
    pub fn canonical(&self) -> String {
        let mut text = String::new();
        if self.epoch != 0 {
            text.push_str(&format!("{}!", self.epoch));
        }
        let release = (0..self.release_len)
            .map(|index| self.release.get(index).copied().unwrap_or(0).to_string())
            .collect::<Vec<_>>();
        text.push_str(&release.join("."));
        if let Some((kind, number)) = self.pre {
            let kind = match kind {
                PreKind::Alpha => "a",
                PreKind::Beta => "b",
                PreKind::ReleaseCandidate => "rc",
            };
            text.push_str(&format!("{kind}{number}"));
        }
        if let Some(number) = self.post {
            text.push_str(&format!(".post{number}"));
        }
        if let Some(number) = self.dev {
            text.push_str(&format!(".dev{number}"));
        }
        if let Some(local) = &self.local {
            let parts = local
                .iter()
                .map(|part| match part {
                    LocalPart::Numeric(number) => number.to_string(),
                    LocalPart::Alpha(text) => text.clone(),
                })
                .collect::<Vec<_>>();
            text.push_str(&format!("+{}", parts.join(".")));
        }
        text
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

impl PartialEq for Version {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for Version {}

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

/// The pre-, post- and dev-release parts, in that order, each optional,
/// as PEP 440 (and `packaging`) spell them: at most one `.`, `-` or `_`
/// before a part and between its letters and its number, and an implicit
/// post-release only as `-N`. If anything is left over the whole suffix is
/// refused: which part the leftover "belongs" to is a guess (`.rc1` after
/// `a1` half-reads as the post-release `.r`), so the message quotes it all.
fn parse_suffix(
    suffix: &str,
) -> Result<(Option<(PreKind, u64)>, Option<u64>, Option<u64>), String> {
    let mut rest = suffix;
    let pre = take_part(
        &mut rest,
        &[
            ("alpha", PreKind::Alpha),
            ("a", PreKind::Alpha),
            ("beta", PreKind::Beta),
            ("b", PreKind::Beta),
            ("preview", PreKind::ReleaseCandidate),
            ("pre", PreKind::ReleaseCandidate),
            ("rc", PreKind::ReleaseCandidate),
            ("c", PreKind::ReleaseCandidate),
        ],
    )?;
    let post = match rest.strip_prefix('-') {
        Some(after) if after.starts_with(|c: char| c.is_ascii_digit()) => {
            let digits = after.len() - after.trim_start_matches(|c: char| c.is_ascii_digit()).len();
            rest = &after[digits..];
            Some(parse_number(&after[..digits])?)
        }
        _ => take_part(&mut rest, &[("post", ()), ("rev", ()), ("r", ())])?.map(|((), n)| n),
    };
    let dev = take_part(&mut rest, &[("dev", ())])?.map(|((), n)| n);
    if !rest.is_empty() {
        return Err(format!("unrecognized version suffix `{suffix}`"));
    }
    Ok((pre, post, dev))
}

/// One `[sep]<word>[sep][digits]` part, the first word that matches (list
/// longer spellings first). Both separators and the number are optional on
/// their own, as in `packaging`: `1.0a.` is `1.0a0`. An absent number is 0.
fn take_part<T: Copy>(rest: &mut &str, words: &[(&str, T)]) -> Result<Option<(T, u64)>, String> {
    let text = *rest;
    let body = text.strip_prefix(['.', '-', '_']).unwrap_or(text);
    let Some((after, value)) = words
        .iter()
        .find_map(|(word, value)| body.strip_prefix(word).map(|after| (after, *value)))
    else {
        return Ok(None);
    };
    let number_start = after.strip_prefix(['.', '-', '_']).unwrap_or(after);
    let digits = number_start.len()
        - number_start
            .trim_start_matches(|c: char| c.is_ascii_digit())
            .len();
    let number = if digits == 0 {
        0
    } else {
        parse_number(&number_start[..digits])?
    };
    *rest = &number_start[digits..];
    Ok(Some((value, number)))
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

/// Evaluate one environment-marker comparison `version op target` the way
/// `packaging` does: if `op target` is one PEP 440 specifier, compare as
/// versions, pre-releases included (`3.13.0rc1 > 3.12.14` holds), and
/// refuse a `version` that is not one. `None` means `op target` is not a
/// specifier, and the caller compares strings instead.
pub fn marker_version_matches(op: &str, target: &str, version: &str) -> io::Result<Option<bool>> {
    let source = "environment marker";
    let target = target.trim();
    // One specifier: no second clause after a space, `,` or `||`, and not
    // the Poetry-only bare `*`.
    if target.is_empty()
        || target == "*"
        || target.contains(|c: char| c.is_whitespace() || c == ',' || c == '|')
    {
        return Ok(None);
    }
    let specifier = if op == "===" {
        None
    } else {
        match SpecifierSet::parse(&format!("{op}{target}"), source) {
            Ok(specifier) => Some(specifier),
            // A number past u64 is a valid specifier tog cannot hold, not
            // an invalid one: comparing it as a string would be a guess.
            Err(error)
                if error
                    .to_string()
                    .ends_with("numeric version segment is too large") =>
            {
                return Err(error)
            }
            Err(_) => return Ok(None),
        }
    };
    let candidate = Version::parse(version).map_err(|why| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{source}: invalid PEP 440 version `{version}`: {why}"),
        )
    })?;
    Ok(Some(match specifier {
        Some(specifier) => specifier.matches_raw(&candidate),
        // Arbitrary equality: the normalized candidate against the text,
        // case-insensitively, as `packaging` compares them.
        None => candidate.canonical().eq_ignore_ascii_case(target),
    }))
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

    /// Equality and ordering give one answer, so a set or map of versions
    /// can never hold `1.0` and `1.0.0` as two entries.
    #[test]
    fn equality_agrees_with_ordering() {
        for (left, right) in [
            ("1.0", "1.0.0"),
            ("1", "1.0.0.0"),
            ("1.0A1", "1.0a1"),
            ("1.0-post1", "1.0.post1"),
            ("0!2.1", "2.1"),
            ("1.0+Local.1", "1.0+local.1"),
        ] {
            let (a, b) = (
                Version::parse(left).unwrap(),
                Version::parse(right).unwrap(),
            );
            assert_eq!(a.cmp(&b), Ordering::Equal, "{left} {right}");
            assert_eq!(a, b, "{left} {right}");
        }
        for (left, right) in [("1.0", "1.0.1"), ("1.0", "1.0+local"), ("1.0", "1.0.post0")] {
            let (a, b) = (
                Version::parse(left).unwrap(),
                Version::parse(right).unwrap(),
            );
            assert_ne!(a.cmp(&b), Ordering::Equal, "{left} {right}");
            assert_ne!(a, b, "{left} {right}");
        }
    }

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

/// Versions come from lock files and package indexes. A string that is not
/// a PEP 440 version is refused with the rule it breaks, never read as some
/// other version.
#[cfg(test)]
mod rejection_tests {
    use super::*;

    #[test]
    fn malformed_versions_are_refused_with_the_rule_they_break() {
        let cases = [
            ("", "version is empty"),
            ("   ", "version is empty"),
            ("1.0+", "invalid local version"),
            ("1.0+a+b", "invalid local version"),
            ("1.0+a..b", "invalid local version segment"),
            ("1.0+a.", "invalid local version segment"),
            ("1.0+a!b", "invalid local version segment"),
            ("!1.0", "invalid epoch"),
            ("x!1.0", "invalid epoch"),
            ("1a!1.0", "invalid epoch"),
            ("1!", "release segment is missing"),
            ("a1", "release segment is missing"),
            ("v", "release segment is missing"),
            ("1..0", "unrecognized version suffix `..0`"),
            (".1", "release segment is missing"),
            // Each part appears once, in the order pre, post, dev.
            ("1.0a1a2", "unrecognized version suffix `a1a2`"),
            ("1.0a1.rc1", "unrecognized version suffix `a1.rc1`"),
            (
                "1.0.post1.post2",
                "unrecognized version suffix `.post1.post2`",
            ),
            ("1.0-1-2", "unrecognized version suffix `-1-2`"),
            ("1.0.dev1.dev2", "unrecognized version suffix `.dev1.dev2`"),
            (
                "1.0.dev1.post1",
                "unrecognized version suffix `.dev1.post1`",
            ),
            ("1.0.post1a1", "unrecognized version suffix `.post1a1`"),
            // At most one separator, and never a dangling one.
            ("1.0.", "unrecognized version suffix `.`"),
            ("1.0-", "unrecognized version suffix `-`"),
            ("1.0..a1", "unrecognized version suffix `..a1`"),
            ("1.0__1", "unrecognized version suffix `__1`"),
            ("1.0.+abc", "unrecognized version suffix `.`"),
            ("1.0-+abc", "unrecognized version suffix `-`"),
            ("1.0a..1", "unrecognized version suffix `a..1`"),
            ("1.0foo", "unrecognized version suffix `foo`"),
            ("1.0-x", "unrecognized version suffix `-x`"),
            (
                "99999999999999999999",
                "numeric version segment is too large",
            ),
            (
                "99999999999999999999!1",
                "numeric version segment is too large",
            ),
            (
                "1.0+99999999999999999999",
                "numeric version segment is too large",
            ),
        ];
        for (text, why) in cases {
            assert_eq!(Version::parse(text), Err(why.to_string()), "{text:?}");
        }
    }

    /// Spellings PEP 440 accepts and normalizes, including the implicit
    /// post-release `1.0-1`.
    #[test]
    fn valid_spellings_normalize_to_the_same_version() {
        let same = [
            ("1.0-1", "1.0.post1"),
            ("1.0_r2", "1.0.post2"),
            ("1.0rev3", "1.0.post3"),
            ("v1.0", "1.0"),
            ("V1.0RC1", "1.0rc1"),
            ("1.0-alpha.1", "1.0a1"),
            ("1.0.post", "1.0.post0"),
            ("1.0-dev", "1.0.dev0"),
            ("0!1.0", "1.0"),
            ("1.0+Ubuntu.1", "1.0+ubuntu.1"),
            ("1.0+local-7", "1.0+local.7"),
            ("1.0.a1", "1.0a1"),
            ("1.0a1-1", "1.0a1.post1"),
            ("1.0.0-rc.1", "1.0.0rc1"),
            ("1.0_pre_2", "1.0rc2"),
            ("1.0a1.post2.dev3", "1.0a1.post2.dev3"),
            ("1.0a.", "1.0a0"),
            ("1.0post_", "1.0.post0"),
            ("1.0dev-", "1.0.dev0"),
            ("1.0a--post1", "1.0a0.post1"),
        ];
        for (spelled, normal) in same {
            let spelled_version = Version::parse(spelled).unwrap();
            assert_eq!(
                spelled_version.cmp(&Version::parse(normal).unwrap()),
                Ordering::Equal,
                "{spelled} vs {normal}"
            );
        }
        for (spelled, canonical) in [
            ("V1.0-RC1", "1.0rc1"),
            ("1.0-1", "1.0.post1"),
            ("1.0.0", "1.0.0"),
            ("3.12.14.0", "3.12.14.0"),
            ("0!1.0", "1.0"),
            ("2!1.0_ALPHA-2.r3-dev4", "2!1.0a2.post3.dev4"),
            ("1.0b", "1.0b0"),
            ("1.0+Ubuntu-01.X", "1.0+ubuntu.1.x"),
        ] {
            assert_eq!(
                Version::parse(spelled).unwrap().canonical(),
                canonical,
                "{spelled}"
            );
        }
        assert!(Version::parse("1!1.0").unwrap() > Version::parse("2.0").unwrap());
        assert!(Version::parse("1.0+local").unwrap().has_local());
    }

    #[test]
    fn a_malformed_version_or_specifier_is_refused_by_the_matchers() {
        let error = matches_specifier(">=1.0", "1..0").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{error}");
        assert_eq!(
            error.to_string(),
            "specifier: invalid PEP 440 version `1..0`: unrecognized version suffix `..0`"
        );
        let error = matches_specifiers_with_candidates(&[">=1.0"], "1.0", &["1.0+"]).unwrap_err();
        assert_eq!(
            error.to_string(),
            "specifier: invalid PEP 440 version `1.0+`: invalid local version"
        );
        let error = matches_specifier(">=1..0", "1.0").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{error}");
        assert!(
            error
                .to_string()
                .starts_with("specifier: invalid PEP 440 specifier `>=1..0`"),
            "{error}"
        );
        assert!(matches_specifier(">=1.0", "1.0-1").unwrap());
    }
}

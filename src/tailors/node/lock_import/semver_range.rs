//! npm semver ranges (node-semver's grammar and `satisfies` without
//! `includePrerelease`), for pnpm `patchedDependencies` range keys.
//!
//! Grammar: `||`-separated comparator sets; each set is whitespace-separated
//! comparators (`<`, `<=`, `>`, `>=`, `=`, `^`, `~`, `~>`, or none) over
//! full or partial versions with `x`/`X`/`*` wildcards, or a hyphen range
//! `a - b`. Desugaring follows node-semver's `replaceCaret`, `replaceTilde`,
//! `replaceXRange` and `hyphenReplace`. Anything else is an error, so a
//! range tog cannot read is refused rather than guessed.

use super::yarn1::{parse_semver, semver_cmp, Semver, SemverIdentifier};
use super::*;
use std::cmp::Ordering;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Lt,
    Le,
    Gt,
    Ge,
    Eq,
}

#[derive(Debug, Clone)]
struct Comparator {
    op: Op,
    version: Semver,
}

/// A partial version: `None` is a wildcard or a missing part.
#[derive(Debug, Clone)]
struct Partial {
    major: Option<u64>,
    minor: Option<u64>,
    patch: Option<u64>,
    prerelease: Vec<SemverIdentifier>,
}

fn version(major: u64, minor: u64, patch: u64, prerelease: Vec<SemverIdentifier>) -> Semver {
    Semver {
        major,
        minor,
        patch,
        prerelease,
    }
}

/// The `-0` node-semver puts on exclusive upper bounds so that prereleases
/// of the next version stay out.
fn floor(major: u64, minor: u64, patch: u64) -> Semver {
    version(major, minor, patch, vec![SemverIdentifier::Numeric(0)])
}

fn parse_partial(text: &str) -> Option<Partial> {
    let text = text.trim_start_matches(['v', '=']).trim();
    if text.is_empty() {
        return None;
    }
    let (text, _build) = text.split_once('+').unwrap_or((text, ""));
    let (core, prerelease) = match text.split_once('-') {
        Some((core, prerelease)) => (core, Some(prerelease)),
        None => (text, None),
    };
    let parts = core.split('.').collect::<Vec<_>>();
    if parts.len() > 3 {
        return None;
    }
    let mut numbers = [None; 3];
    let mut wildcard = false;
    for (index, part) in parts.iter().enumerate() {
        if matches!(*part, "x" | "X" | "*") {
            wildcard = true;
            continue;
        }
        // A number after a wildcard (`1.x.3`) is not a version.
        if wildcard
            || part.is_empty()
            || !part.bytes().all(|byte| byte.is_ascii_digit())
            || (part.len() > 1 && part.starts_with('0'))
        {
            return None;
        }
        numbers[index] = Some(part.parse().ok()?);
    }
    let prerelease = match prerelease {
        Some(prerelease) => {
            if numbers.iter().any(Option::is_none) {
                return None;
            }
            parse_semver(&format!("0.0.0-{prerelease}"), false)?.prerelease
        }
        None => Vec::new(),
    };
    Some(Partial {
        major: numbers[0],
        minor: numbers[1],
        patch: numbers[2],
        prerelease,
    })
}

fn comparator(op: Op, version: Semver) -> Comparator {
    Comparator { op, version }
}

/// One comparator token (operator already split off) as the comparators it
/// desugars to. An empty result matches every version; `None` is an error.
fn desugar(op: &str, partial: &Partial) -> Option<Vec<Comparator>> {
    let Partial {
        major,
        minor,
        patch,
        prerelease,
    } = partial.clone();
    let lower = || {
        version(
            major.unwrap_or(0),
            minor.unwrap_or(0),
            patch.unwrap_or(0),
            prerelease.clone(),
        )
    };
    Some(match op {
        "^" => {
            let Some(major) = major else {
                return Some(vec![comparator(Op::Ge, version(0, 0, 0, Vec::new()))]);
            };
            let upper = match (major, minor, patch) {
                (0, None, _) => floor(1, 0, 0),
                (0, Some(0), None) => floor(0, 1, 0),
                (0, Some(0), Some(patch)) => floor(0, 0, patch + 1),
                (0, Some(minor), _) => floor(0, minor + 1, 0),
                (major, _, _) => floor(major + 1, 0, 0),
            };
            vec![comparator(Op::Ge, lower()), comparator(Op::Lt, upper)]
        }
        "~" | "~>" => {
            let Some(major) = major else {
                return Some(vec![comparator(Op::Ge, version(0, 0, 0, Vec::new()))]);
            };
            let upper = match minor {
                None => floor(major + 1, 0, 0),
                Some(minor) => floor(major, minor + 1, 0),
            };
            vec![comparator(Op::Ge, lower()), comparator(Op::Lt, upper)]
        }
        "" | "=" => match (major, minor, patch) {
            (None, _, _) => vec![comparator(Op::Ge, version(0, 0, 0, Vec::new()))],
            (Some(major), None, _) => vec![
                comparator(Op::Ge, lower()),
                comparator(Op::Lt, floor(major + 1, 0, 0)),
            ],
            (Some(major), Some(minor), None) => vec![
                comparator(Op::Ge, lower()),
                comparator(Op::Lt, floor(major, minor + 1, 0)),
            ],
            (Some(_), Some(_), Some(_)) => vec![comparator(Op::Eq, lower())],
        },
        ">" | ">=" | "<" | "<=" => {
            let Some(major) = major else {
                // `>*` and `<*` match nothing; `>=*` and `<=*` match anything.
                return Some(match op {
                    ">" | "<" => vec![comparator(Op::Lt, version(0, 0, 0, Vec::new()))],
                    _ => vec![comparator(Op::Ge, version(0, 0, 0, Vec::new()))],
                });
            };
            if patch.is_some() {
                let op = match op {
                    ">" => Op::Gt,
                    ">=" => Op::Ge,
                    "<" => Op::Lt,
                    _ => Op::Le,
                };
                return Some(vec![comparator(op, lower())]);
            }
            // Partial versions: node-semver's replaceXRange.
            let next = match minor {
                None => (major + 1, 0),
                Some(minor) => (major, minor + 1),
            };
            match op {
                ">" => vec![comparator(Op::Ge, version(next.0, next.1, 0, Vec::new()))],
                ">=" => vec![comparator(Op::Ge, lower())],
                "<" => vec![comparator(Op::Lt, floor(major, minor.unwrap_or(0), 0))],
                _ => vec![comparator(Op::Lt, floor(next.0, next.1, 0))],
            }
        }
        _ => return None,
    })
}

fn split_operator(token: &str) -> (&str, &str) {
    for op in ["<=", ">=", "~>", "<", ">", "=", "^", "~"] {
        if let Some(rest) = token.strip_prefix(op) {
            return (op, rest);
        }
    }
    ("", token)
}

fn parse_set(text: &str) -> Option<Vec<Comparator>> {
    let raw = text.split_whitespace().collect::<Vec<_>>();
    if raw.len() == 3 && raw[1] == "-" {
        let from = parse_partial(raw[0])?;
        let to = parse_partial(raw[2])?;
        let mut set = desugar(">=", &from)?;
        set.extend(desugar("<=", &to)?);
        return Some(set);
    }
    // node-semver allows whitespace between an operator and its version.
    let mut tokens = Vec::new();
    let mut pending = String::new();
    for token in raw {
        let (op, rest) = split_operator(token);
        if rest.is_empty() && !op.is_empty() {
            pending.push_str(op);
            continue;
        }
        tokens.push(format!("{pending}{token}"));
        pending.clear();
    }
    if !pending.is_empty() {
        return None;
    }
    if tokens.is_empty() {
        return Some(vec![comparator(Op::Ge, version(0, 0, 0, Vec::new()))]);
    }
    let mut set = Vec::new();
    for token in &tokens {
        let (op, rest) = split_operator(token);
        set.extend(desugar(op, &parse_partial(rest)?)?);
    }
    Some(set)
}

fn test(comparator: &Comparator, candidate: &Semver) -> bool {
    let ordering = semver_cmp(candidate, &comparator.version);
    match comparator.op {
        Op::Lt => ordering == Ordering::Less,
        Op::Le => ordering != Ordering::Greater,
        Op::Gt => ordering == Ordering::Greater,
        Op::Ge => ordering != Ordering::Less,
        Op::Eq => ordering == Ordering::Equal,
    }
}

fn set_matches(set: &[Comparator], candidate: &Semver) -> bool {
    if !set.iter().all(|comparator| test(comparator, candidate)) {
        return false;
    }
    // A prerelease only satisfies a set that names a prerelease of the same
    // major.minor.patch (node-semver `testSet`).
    candidate.prerelease.is_empty()
        || set.iter().any(|comparator| {
            !comparator.version.prerelease.is_empty()
                && (
                    comparator.version.major,
                    comparator.version.minor,
                    comparator.version.patch,
                ) == (candidate.major, candidate.minor, candidate.patch)
        })
}

/// A parsed npm range.
#[derive(Debug, Clone)]
pub(super) struct Range(Vec<Vec<Comparator>>);

impl Range {
    pub(super) fn parse(text: &str) -> io::Result<Range> {
        text.split("||")
            .map(parse_set)
            .collect::<Option<Vec<_>>>()
            .map(Range)
            .ok_or_else(|| err(format!("{text:?} is not a semver range tog can read")))
    }

    /// Whether `candidate` satisfies the range. A version that is not
    /// semver (a `file:` or git reference) satisfies nothing.
    pub(super) fn satisfies(&self, candidate: &str) -> bool {
        let Some(candidate) = parse_semver(candidate, false) else {
            return false;
        };
        self.0.iter().any(|set| set_matches(set, &candidate))
    }
}

#[cfg(test)]
mod tests {
    use super::Range;

    #[track_caller]
    fn check(range: &str, yes: &[&str], no: &[&str]) {
        let parsed = Range::parse(range).unwrap();
        for version in yes {
            assert!(
                parsed.satisfies(version),
                "{version} should satisfy {range}"
            );
        }
        for version in no {
            assert!(
                !parsed.satisfies(version),
                "{version} should not satisfy {range}"
            );
        }
    }

    /// Cases from node-semver's range-include and range-exclude fixtures.
    #[test]
    fn npm_ranges_match_node_semver() {
        check(
            "^1.2.3",
            &["1.2.3", "1.9.0"],
            &["2.0.0", "1.2.2", "2.0.0-0"],
        );
        check("^0.2.3", &["0.2.3", "0.2.9"], &["0.3.0", "0.2.2"]);
        check("^0.0.3", &["0.0.3"], &["0.0.4", "0.0.2"]);
        check("^1.2", &["1.2.0", "1.99.0"], &["1.1.9", "2.0.0"]);
        check("^0.x", &["0.0.0", "0.9.9"], &["1.0.0"]);
        check("^0.0", &["0.0.9"], &["0.1.0"]);
        check("~1.2.3", &["1.2.3", "1.2.9"], &["1.3.0"]);
        check("~1.2", &["1.2.0", "1.2.9"], &["1.3.0"]);
        check("~1", &["1.0.0", "1.9.9"], &["2.0.0"]);
        check("~> 1.2", &["1.2.5"], &["1.3.0"]);
        check("1.x", &["1.0.0", "1.9.9"], &["2.0.0", "0.9.9"]);
        check("1.2.*", &["1.2.0", "1.2.7"], &["1.3.0"]);
        check("1", &["1.4.0"], &["2.0.0"]);
        check("*", &["0.0.0", "9.9.9"], &["1.0.0-beta"]);
        check("", &["1.0.0"], &[]);
        check(">1.2", &["1.3.0"], &["1.2.9"]);
        check(">=1", &["1.0.0"], &["0.9.9"]);
        check("<1.2", &["1.1.9"], &["1.2.0", "1.2.0-beta"]);
        check("<=1.2", &["1.2.9"], &["1.3.0"]);
        check(">= 1.2.3 < 2", &["1.2.3", "1.99.0"], &["2.0.0", "1.2.2"]);
        check("1.2.3 - 2.3", &["1.2.3", "2.3.9"], &["2.4.0", "1.2.2"]);
        check("1 - 2", &["1.0.0", "2.9.9"], &["3.0.0"]);
        check("^1.0.0 || ^3.0.0", &["1.5.0", "3.1.0"], &["2.0.0"]);
        check("=1.2.3", &["1.2.3"], &["1.2.4"]);
        check("v1.2.3", &["1.2.3"], &["1.2.4"]);
        check(
            "^1.2.3-beta.2",
            &["1.2.3-beta.2", "1.2.3-beta.4", "1.2.3"],
            &["1.2.3-beta.1", "1.2.4-beta.2"],
        );
        check(
            ">1.2.3-alpha.3",
            &["1.2.3-alpha.7", "3.4.5"],
            &["3.4.5-alpha.9"],
        );
        check("^1.0.0", &[], &["file:vendor/a", "1.0.0-rc.1"]);
    }

    #[test]
    fn unreadable_ranges_are_refused() {
        for range in [
            "latest",
            "1.x.3",
            "^",
            "01.2.3",
            ">= ",
            "1.2.3 -",
            "workspace:*",
        ] {
            assert!(Range::parse(range).is_err(), "{range:?} should be refused");
        }
    }
}

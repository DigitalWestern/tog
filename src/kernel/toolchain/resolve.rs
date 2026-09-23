//! Lowering declarative source rows to a selection [`Request`].
//!
//! `input::discover` reads the files; this module turns the rows it found
//! into the one request grammar `select` understands, per ecosystem and in
//! that ecosystem's precedence order. Every request on one primary
//! component applies together, so two sources that both state a version
//! intersect rather than override. Nothing here reads a file, starts a
//! program, or consults the host: it is a pure function of the rows.
//!
//! An unsupported spelling is refused by name instead of being approximated.
//! A toolchain that is off by a patch is a silently wrong build; a refusal
//! that names the file and the next command is a two-minute fix.

use super::input::InputRow;
use super::select::{Op, Request, Specifier, Version, VersionRequest};
use super::{invalid, Bundle, Catalog};
use std::io;

/// The next step every refusal in this module names.
const UPDATE_HINT: &str = "run `tog update --toolchain`";

/// What `.python-version` accepts, spelled the way the refusal spells it.
const PYTHON_HINT: &str = "put an X.Y, X.Y.Z, or supported specifier in .python-version, then run `tog update --toolchain`";

/// The value a row holds, looked up by the (path, field) pair discovery
/// recorded it under. A row with no value reads the same as no row.
fn value<'a>(rows: &'a [InputRow], path: &str, field: &str) -> Option<&'a str> {
    rows.iter()
        .find(|row| row.path.as_os_str() == path && row.field == field)
        .and_then(|row| row.value.as_deref())
}

/// A fully spelled version is exact; a shorter one names the newest release
/// under it. `3.12.14` is one release, `3.12` is a line.
fn exact_or_prefix(version: Version) -> VersionRequest {
    if version.parts().len() >= 3 {
        VersionRequest::Exact(version)
    } else {
        VersionRequest::Prefix(version)
    }
}

fn parse_version(field: &str, text: &str) -> io::Result<Version> {
    Version::parse(text).map_err(|error| invalid(format!("{field}: {error}; {UPDATE_HINT}")))
}

/// The one supported operator set: PEP 440's `>=`, `<`, `==`, `~=`, `!=`.
/// `>` and `<=` are refused rather than approximated, because a lock minted
/// from an approximation is wrong in a way nobody reviews.
fn parse_op(term: &str) -> Option<(Op, &str)> {
    for (text, op) in [
        (">=", Op::Ge),
        ("==", Op::Eq),
        ("~=", Op::Compatible),
        ("!=", Op::Ne),
        ("<", Op::Lt),
    ] {
        if let Some(rest) = term.strip_prefix(text) {
            // `<=` must not be read as `<`.
            if text == "<" && rest.starts_with('=') {
                return None;
            }
            return Some((op, rest));
        }
    }
    None
}

/// A comma-joined specifier set over the supported operators.
fn specifier_set(field: &str, text: &str) -> io::Result<VersionRequest> {
    let mut specifiers = Vec::new();
    for term in text.split(',') {
        let term = term.trim();
        let (op, rest) = parse_op(term).ok_or_else(|| {
            invalid(format!(
                "{field}: {term} is not a supported version specifier; use >=, <, ==, ~=, or != and {UPDATE_HINT}"
            ))
        })?;
        let version = parse_version(field, rest.trim())?;
        specifiers.push(
            Specifier::new(op, version)
                .map_err(|error| invalid(format!("{field}: {error}; {UPDATE_HINT}")))?,
        );
    }
    if specifiers.is_empty() {
        return Err(invalid(format!("{field}: empty version specifier set")));
    }
    Ok(VersionRequest::Specifiers(specifiers))
}

/// The request `.python-version` states, or the refusal uv's own grammar
/// would give it.
fn python_version_request(text: &str) -> io::Result<VersionRequest> {
    let lower = text.to_ascii_lowercase();
    if lower.contains("pypy")
        || lower.contains("miniconda")
        || lower.contains("graalpy")
        || lower == "system"
        || lower.contains("-dev")
        || lower.ends_with('t')
        || lower.contains("free-thread")
        || lower.contains("freethread")
    {
        return Err(invalid(format!(
            ".python-version: unsupported Python interpreter request `{text}`; {PYTHON_HINT}"
        )));
    }
    if let Some(prefix) = text.strip_suffix(".*") {
        if let Ok(version) = Version::parse(prefix) {
            return Ok(VersionRequest::Prefix(version));
        }
    }
    if let Ok(version) = Version::parse(text) {
        return Ok(exact_or_prefix(version));
    }
    if let Ok(request) = specifier_set(".python-version", text) {
        return Ok(request);
    }
    Err(invalid(format!(
        ".python-version: invalid .python-version request `{text}`; {PYTHON_HINT}"
    )))
}

/// A Poetry constraint: one alternative, or `||`-joined alternatives that
/// lower to one [`VersionRequest::AnyOf`]. `*` (alone or as any
/// alternative) admits every release and states nothing.
fn poetry_python_request(text: &str) -> io::Result<Option<VersionRequest>> {
    let mut alternatives = Vec::new();
    for alternative in text.split("||") {
        if alternative.trim() == "*" {
            return Ok(None);
        }
        alternatives.push(poetry_python_alternative(alternative)?);
    }
    if alternatives.len() == 1 {
        return Ok(alternatives.pop());
    }
    Ok(Some(VersionRequest::AnyOf(
        alternatives.into_iter().map(|one| vec![one]).collect(),
    )))
}

/// Poetry's caret and tilde over the same grammar: `^3.9` is `>=3.9,<4`,
/// `~3.9` is `>=3.9,<3.10`.
fn poetry_python_alternative(text: &str) -> io::Result<VersionRequest> {
    const FIELD: &str = "tool.poetry.dependencies.python";
    let bounded = |rest: &str, keep: usize| -> io::Result<VersionRequest> {
        let lower = parse_version(FIELD, rest.trim())?;
        let mut upper: Vec<u64> = lower.parts().iter().copied().take(keep).collect();
        while upper.len() < keep {
            upper.push(0);
        }
        let last = upper.len() - 1;
        upper[last] += 1;
        let upper: Vec<String> = upper.iter().map(u64::to_string).collect();
        let upper = parse_version(FIELD, &upper.join("."))?;
        Ok(VersionRequest::Specifiers(vec![
            Specifier::new(Op::Ge, lower).map_err(|error| invalid(format!("{FIELD}: {error}")))?,
            Specifier::new(Op::Lt, upper).map_err(|error| invalid(format!("{FIELD}: {error}")))?,
        ]))
    };
    if let Some(rest) = text.trim().strip_prefix('^') {
        return bounded(rest, 1);
    }
    if let Some(rest) = text.trim().strip_prefix('~') {
        let parts = parse_version(FIELD, rest.trim())?.parts().len();
        return bounded(rest, parts.min(2));
    }
    if let Some(prefix) = text.trim().strip_suffix(".*") {
        return Ok(VersionRequest::Prefix(parse_version(FIELD, prefix)?));
    }
    specifier_set(FIELD, text.trim())
}

/// The refusal every unreadable `engines.node` range gets.
fn node_unsupported(whole: &str) -> io::Error {
    invalid(format!(
        "engines.node range {whole} is not supported; put an exact version in .node-version"
    ))
}

fn node_version(whole: &str, parts: &[u64]) -> io::Result<Version> {
    let text: Vec<String> = parts.iter().map(u64::to_string).collect();
    Version::parse(&text.join(".")).map_err(|_| node_unsupported(whole))
}

/// The first version past everything `parts` spells, keeping its component
/// count: `1.2.3` gives `1.2.4`, `24.0` gives `24.1`, `1` gives `2`. Node
/// versions are integer triples with no prerelease rows in the catalog, so
/// `>X` is `>=` this and `<=X` is `<` this.
///
/// `primitive` marks a full three-component `>X` or `<=X`, which node
/// semver keeps as a comparator on X itself, so its bump may pass the
/// component limit. Every other bound node semver generates (partials,
/// caret, tilde, a partial hyphen end) must stay within it, as node semver
/// refuses those ranges.
fn node_next(whole: &str, parts: &[u64], primitive: bool) -> io::Result<Version> {
    let mut parts = parts.to_vec();
    let last = parts.last_mut().ok_or_else(|| node_unsupported(whole))?;
    *last = last
        .checked_add(1)
        .filter(|next| primitive || *next <= crate::kernel::semver::MAX_COMPONENT)
        .ok_or_else(|| node_unsupported(whole))?;
    node_version(whole, &parts)
}

/// `>= low` and `< high`: the explicit bounds every partial lowers to, so a
/// zero-bearing line (`24.0.x`) stays `>=24.0,<24.1` rather than widening.
fn node_bounds(
    whole: &str,
    low: Option<&[u64]>,
    high: Option<Version>,
) -> io::Result<Vec<VersionRequest>> {
    let mut terms = Vec::new();
    if let Some(low) = low {
        terms.push(node_specifier(Op::Ge, node_version(whole, low)?)?);
    }
    if let Some(high) = high {
        terms.push(node_specifier(Op::Lt, high)?);
    }
    Ok(terms)
}

fn node_specifier(op: Op, version: Version) -> io::Result<VersionRequest> {
    Ok(VersionRequest::Specifiers(vec![Specifier::new(
        op, version,
    )
    .map_err(|error| invalid(format!("engines.node: {error}")))?]))
}

/// A bare partial: exact at three components, otherwise its whole line.
fn node_line(whole: &str, parts: &[u64]) -> io::Result<Vec<VersionRequest>> {
    if parts.len() == 3 {
        return Ok(vec![VersionRequest::Exact(node_version(whole, parts)?)]);
    }
    node_bounds(whole, Some(parts), Some(node_next(whole, parts, false)?))
}

/// The numeric components of a parsed partial, refusing what a toolchain
/// request never takes: a prerelease suffix.
fn kernel_parts(whole: &str, partial: &crate::kernel::semver::Partial) -> io::Result<Vec<u64>> {
    if !partial.prerelease.is_empty() {
        return Err(node_unsupported(whole));
    }
    Ok(partial.parts.clone())
}

fn kernel_term(whole: &str, term: &crate::kernel::semver::Term) -> io::Result<Vec<VersionRequest>> {
    use crate::kernel::semver::{Op as NpmOp, Term};
    let (op, parts) = match term {
        Term::Hyphen { low, high } => {
            let low = kernel_parts(whole, low)?;
            let high = kernel_parts(whole, high)?;
            let high = if high.is_empty() {
                None
            } else {
                Some(node_next(whole, &high, high.len() == 3)?)
            };
            return node_bounds(
                whole,
                Some(&low).filter(|low| !low.is_empty()).map(|low| &low[..]),
                high,
            );
        }
        Term::Comparator { op, version } => (*op, kernel_parts(whole, version)?),
    };
    match op {
        NpmOp::Ge if parts.is_empty() => Ok(Vec::new()),
        NpmOp::Ge => node_bounds(whole, Some(&parts[..]), None),
        NpmOp::Le if parts.is_empty() => Ok(Vec::new()),
        NpmOp::Le => node_bounds(
            whole,
            None,
            Some(node_next(whole, &parts, parts.len() == 3)?),
        ),
        // `>*` and `<*` admit nothing: refuse rather than lock nothing.
        NpmOp::Gt | NpmOp::Lt if parts.is_empty() => Err(node_unsupported(whole)),
        NpmOp::Gt => Ok(vec![node_specifier(
            Op::Ge,
            node_next(whole, &parts, parts.len() == 3)?,
        )?]),
        NpmOp::Lt => node_bounds(whole, None, Some(node_version(whole, &parts)?)),
        _ if parts.is_empty() => Ok(Vec::new()),
        NpmOp::Caret => {
            let keep = parts
                .iter()
                .position(|part| *part != 0)
                .map_or(parts.len(), |index| index + 1)
                .min(parts.len());
            node_bounds(
                whole,
                Some(&parts[..]),
                Some(node_next(whole, &parts[..keep], false)?),
            )
        }
        NpmOp::Tilde => {
            let keep = parts.len().min(2);
            node_bounds(
                whole,
                Some(&parts[..]),
                Some(node_next(whole, &parts[..keep], false)?),
            )
        }
        NpmOp::Eq => node_line(whole, &parts),
    }
}

/// Every `engines.node` term, which all apply together. `*` and an empty
/// range state nothing. A `||` range is a set of alternatives, each a
/// space-joined set of comparators: it lowers to one
/// [`VersionRequest::AnyOf`], or to nothing when any alternative is itself
/// unconstrained (empty, `*`, `x`, `>=0`), since that alternative admits
/// every release.
fn engines_node(text: &str) -> io::Result<Vec<VersionRequest>> {
    let text = text.trim();
    let range = crate::kernel::semver::Range::parse(text).map_err(|_| node_unsupported(text))?;
    // A toolchain request never takes build metadata.
    if range.names_build() {
        return Err(node_unsupported(text));
    }
    let mut alternatives = Vec::new();
    for alternative in range.alternatives() {
        let mut terms = Vec::new();
        for term in alternative {
            terms.extend(kernel_term(text, term)?);
        }
        if terms.is_empty() {
            return Ok(Vec::new());
        }
        alternatives.push(terms);
    }
    if alternatives.len() == 1 {
        return Ok(alternatives.pop().unwrap_or_default());
    }
    Ok(vec![VersionRequest::AnyOf(alternatives)])
}

/// The selection request an ecosystem's consulted rows state. `ecosystem`
/// is the toolchain-input name (`python`, `node`, `rust`, `go`, `ruby`,
/// `elixir`, `dotnet`); `rows` come from `input::discover` in its order.
pub fn request_for(ecosystem: &str, rows: &[InputRow]) -> io::Result<Request> {
    let mut request = Request::newest();
    match ecosystem {
        "python" => {
            if let Some(text) = value(rows, ".python-version", "version") {
                request = request.with("cpython", python_version_request(text)?);
            }
            if let Some(text) = value(rows, "pyproject.toml", "project.requires-python") {
                request = request.with(
                    "cpython",
                    specifier_set("project.requires-python", text.trim())?,
                );
            }
            if let Some(text) = value(rows, "pyproject.toml", "tool.poetry.dependencies.python") {
                if let Some(poetry) = poetry_python_request(text)? {
                    request = request.with("cpython", poetry);
                }
            }
        }
        "node" => {
            if let Some(text) = value(rows, ".node-version", "version") {
                request = request.with(
                    "node",
                    exact_or_prefix(parse_version(".node-version", text)?),
                );
            }
            if let Some(text) = value(rows, "package.json", "engines.node") {
                for term in engines_node(text)? {
                    request = request.with("node", term);
                }
            }
        }
        "rust" => {
            let legacy = value(rows, "rust-toolchain", "toolchain.channel");
            let modern = value(rows, "rust-toolchain.toml", "toolchain.channel");
            if let (Some(a), Some(b)) = (legacy, modern) {
                if a != b {
                    return Err(invalid(format!(
                        "rust-toolchain says {a} and rust-toolchain.toml says {b}; make them agree, then {UPDATE_HINT}"
                    )));
                }
            }
            if let Some(channel) = legacy.or(modern) {
                if channel != "stable" {
                    let version = Version::parse(channel).map_err(|_| {
                        invalid(format!(
                            "rust channel {channel} is not supported; use an exact version or stable"
                        ))
                    })?;
                    request = request.with("rustc", exact_or_prefix(version));
                }
            }
        }
        "go" => {
            let minimum = match value(rows, "go.mod", "go") {
                Some(text) => Some(parse_version("go.mod go directive", text)?),
                None => None,
            };
            match value(rows, "go.mod", "toolchain") {
                Some(text) => {
                    let exact = parse_version("go.mod toolchain directive", text)?;
                    if let Some(minimum) = &minimum {
                        if &exact < minimum {
                            return Err(invalid(format!(
                                "go.mod: toolchain go{exact} does not satisfy the go {minimum} minimum; {UPDATE_HINT}"
                            )));
                        }
                    }
                    request = request.with("go", VersionRequest::Exact(exact));
                }
                None => {
                    if let Some(minimum) = minimum {
                        request = request.with(
                            "go",
                            VersionRequest::Specifiers(vec![Specifier::new(Op::Ge, minimum)
                                .map_err(|error| invalid(format!("go.mod: {error}")))?]),
                        );
                    }
                }
            }
        }
        "ruby" => {
            let pinned = value(rows, ".ruby-version", "version");
            let tools = value(rows, ".tool-versions", "ruby");
            if let (Some(a), Some(b)) = (pinned, tools) {
                if a != b {
                    return Err(invalid(format!(
                        ".ruby-version says {a} and .tool-versions says {b}; make them agree, then {UPDATE_HINT}"
                    )));
                }
            }
            if let Some(text) = pinned.or(tools) {
                request = request.with(
                    "ruby",
                    exact_or_prefix(parse_version(".ruby-version", text)?),
                );
            }
        }
        "elixir" => {
            if let Some(text) = value(rows, ".tool-versions", "erlang") {
                request = request.with(
                    "otp",
                    exact_or_prefix(parse_version(".tool-versions erlang", text)?),
                );
            }
            if let Some(text) = value(rows, ".tool-versions", "elixir") {
                // `1.17.0-otp-27` states the Elixir build's OTP pairing, not
                // a fourth version component.
                let text = text.split("-otp-").next().unwrap_or(text);
                request = request.with(
                    "elixir",
                    exact_or_prefix(parse_version(".tool-versions elixir", text)?),
                );
            }
        }
        "dotnet" => {
            if let Some(text) = value(rows, "global.json", "sdk.version") {
                if value(rows, "global.json", "sdk.rollForward") != Some("disable") {
                    return Err(invalid(
                        "global.json sdk.rollForward must be \"disable\" for an exact toolchain lock",
                    ));
                }
                request = request.with(
                    "dotnet-sdk",
                    VersionRequest::Exact(parse_version("global.json sdk.version", text)?),
                );
            }
        }
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unknown ecosystem '{other}'"),
            ));
        }
    }
    Ok(request)
}

/// The bundle an ecosystem's rows select from `catalog`. The refusal names
/// the ecosystem and the request, because "no release satisfies" is only
/// actionable with both.
pub fn select_for<'a>(
    catalog: &'a Catalog,
    ecosystem: &str,
    rows: &[InputRow],
) -> io::Result<&'a Bundle> {
    let request = request_for(ecosystem, rows)?;
    catalog
        .select(&request)
        .map_err(|error| invalid(format!("{ecosystem} toolchain: {error}")))
}

#[cfg(test)]
mod tests {
    use super::super::fixtures::*;
    use super::*;
    use crate::kernel::platform::Platform;
    use std::path::PathBuf;

    /// One consulted row, with the digest discovery would have recorded.
    fn row(path: &str, field: &str, value: Option<&str>) -> InputRow {
        InputRow {
            path: PathBuf::from(path),
            field: field.to_string(),
            value: value.map(str::to_string),
            absent: value.is_none(),
            sha256: value.map(|_| "a".repeat(64)),
        }
    }

    fn request(ecosystem: &str, rows: &[InputRow]) -> String {
        request_for(ecosystem, rows).unwrap().to_string()
    }

    fn refusal(ecosystem: &str, rows: &[InputRow]) -> String {
        request_for(ecosystem, rows).unwrap_err().to_string()
    }

    fn catalog(ecosystem: &str, component: &str, versions: &[&str]) -> Catalog {
        Catalog::new(
            ecosystem,
            versions
                .iter()
                .map(|version| {
                    bundle(
                        &format!("{component}-{version}"),
                        component,
                        version,
                        Platform::ALL,
                    )
                })
                .collect(),
        )
        .unwrap()
    }

    #[test]
    fn no_source_anywhere_asks_for_the_newest() {
        for ecosystem in ["python", "node", "rust", "go", "ruby", "elixir", "dotnet"] {
            assert_eq!(request(ecosystem, &[]), "newest", "{ecosystem}");
        }
        let catalog = catalog("python", "cpython", &["3.12.14", "3.13.15"]);
        assert_eq!(
            select_for(&catalog, "python", &[]).unwrap().release,
            "cpython-3.13.15"
        );
    }

    #[test]
    fn an_unknown_ecosystem_is_refused() {
        let error = request_for("perl", &[]).unwrap_err();
        assert!(
            error.to_string().contains("unknown ecosystem 'perl'"),
            "{error}"
        );
    }

    #[test]
    fn python_lowers_exact_prefix_and_specifier_sets() {
        let pin = |text: &str| vec![row(".python-version", "version", Some(text))];
        assert_eq!(request("python", &pin("3.12.14")), "cpython ==3.12.14");
        assert_eq!(request("python", &pin("3.12")), "cpython 3.12.*");
        assert_eq!(request("python", &pin("3.12.*")), "cpython 3.12.*");
        assert_eq!(
            request("python", &pin(">=3.11,<3.13")),
            "cpython >=3.11,<3.13"
        );
        assert_eq!(request("python", &pin("~=3.11.2")), "cpython ~=3.11.2");
    }

    #[test]
    fn python_intersects_every_source_that_states_a_version() {
        let rows = vec![
            row(".python-version", "version", Some("3.12")),
            row("pyproject.toml", "project.requires-python", Some(">=3.11")),
            row(
                "pyproject.toml",
                "tool.poetry.dependencies.python",
                Some("^3.9"),
            ),
        ];
        assert_eq!(
            request("python", &rows),
            "cpython 3.12.*; cpython >=3.11; cpython >=3.9,<4"
        );
        let catalog = catalog("python", "cpython", &["3.10.21", "3.12.14", "3.13.15"]);
        assert_eq!(
            select_for(&catalog, "python", &rows).unwrap().release,
            "cpython-3.12.14"
        );
        // Poetry's tilde bounds the minor, its caret the major.
        let tilde = vec![row(
            "pyproject.toml",
            "tool.poetry.dependencies.python",
            Some("~3.9"),
        )];
        assert_eq!(request("python", &tilde), "cpython >=3.9,<3.10");
        let star = vec![row(
            "pyproject.toml",
            "tool.poetry.dependencies.python",
            Some("3.9.*"),
        )];
        assert_eq!(request("python", &star), "cpython 3.9.*");
        // Poetry's `||` joins alternatives; the newest any of them admits wins.
        let either = vec![row(
            "pyproject.toml",
            "tool.poetry.dependencies.python",
            Some(">=3.9,<3.11 || ~3.12"),
        )];
        assert_eq!(
            request("python", &either),
            "cpython >=3.9,<3.11 || >=3.12,<3.13"
        );
        assert_eq!(
            select_for(&catalog, "python", &either).unwrap().release,
            "cpython-3.12.14"
        );
        // Poetry's `*` states nothing, alone or as one alternative.
        for text in ["*", " * ", "^3.9 || *"] {
            let any = vec![row(
                "pyproject.toml",
                "tool.poetry.dependencies.python",
                Some(text),
            )];
            assert_eq!(request("python", &any), "newest", "{text}");
        }
    }

    #[test]
    fn python_refuses_other_interpreters_and_free_text_by_name() {
        for text in [
            "pypy3.10",
            "miniconda3-4.7",
            "graalpy-24",
            "system",
            "3.13-dev",
            "3.13.0t",
            "3.13.0-free-threaded",
        ] {
            let error = refusal("python", &[row(".python-version", "version", Some(text))]);
            assert!(
                error.contains("unsupported Python interpreter request"),
                "{text}: {error}"
            );
            assert!(error.contains(PYTHON_HINT), "{text}: {error}");
        }
        for text in ["/usr/bin/python3", "not a version", ">3.11"] {
            let error = refusal("python", &[row(".python-version", "version", Some(text))]);
            assert!(
                error.contains("invalid .python-version request"),
                "{text}: {error}"
            );
            assert!(error.contains(PYTHON_HINT), "{text}: {error}");
        }
        // An unsupported operator in the metadata names the field it read.
        let error = refusal(
            "python",
            &[row(
                "pyproject.toml",
                "project.requires-python",
                Some(">3.11"),
            )],
        );
        assert!(error.contains("project.requires-python"), "{error}");
        assert!(
            error.contains("not a supported version specifier"),
            "{error}"
        );
        let error = refusal(
            "python",
            &[row(
                "pyproject.toml",
                "project.requires-python",
                Some("<=3.13"),
            )],
        );
        assert!(error.contains("project.requires-python"), "{error}");
    }

    #[test]
    fn node_reads_the_pin_and_the_engines_subset_together() {
        let pin = |text: &str| vec![row(".node-version", "version", Some(text))];
        assert_eq!(request("node", &pin("24.20.0")), "node ==24.20.0");
        assert_eq!(request("node", &pin("24")), "node 24.*");
        assert_eq!(request("node", &pin("24.20")), "node 24.20.*");

        let engines = |text: &str| vec![row("package.json", "engines.node", Some(text))];
        assert_eq!(request("node", &engines("*")), "newest");
        assert_eq!(request("node", &engines("")), "newest");
        assert_eq!(
            request("node", &engines("^24.2.1")),
            "node >=24.2.1; node <25"
        );
        assert_eq!(
            request("node", &engines("~24.2")),
            "node >=24.2; node <24.3"
        );
        assert_eq!(request("node", &engines(">=24.1")), "node >=24.1");
        assert_eq!(request("node", &engines("24.x")), "node >=24; node <25");
        assert_eq!(request("node", &engines("24")), "node >=24; node <25");
        assert_eq!(
            request("node", &engines("=24.0")),
            "node >=24.0; node <24.1"
        );
        assert_eq!(request("node", &engines("=24.20.0")), "node ==24.20.0");
        assert_eq!(
            request("node", &engines(">=24.1 <25")),
            "node >=24.1; node <25"
        );
        for text in [
            "latest",
            ">=",
            "1.2.3 -",
            "- 2.3.4",
            "^20.19 || lts/*",
            "24.0.0.0 - 24.99.0.0",
            "24.0.0.0",
            ">*",
            "1.2.3-beta.1",
            "01.2",
            "9007199254740992",
            "24.x.1",
        ] {
            let error = refusal("node", &engines(text));
            assert!(
                error.contains(&format!("engines.node range {text} is not supported")),
                "{text}: {error}"
            );
            assert!(
                error.contains("put an exact version in .node-version"),
                "{text}: {error}"
            );
        }
        // Both files apply together.
        let rows = vec![
            row(".node-version", "version", Some("24")),
            row("package.json", "engines.node", Some(">=24.10")),
        ];
        assert_eq!(request("node", &rows), "node 24.*; node >=24.10");
        let catalog = catalog("node", "node", &["24.5.0", "24.20.0", "25.1.0"]);
        assert_eq!(
            select_for(&catalog, "node", &rows).unwrap().release,
            "node-24.20.0"
        );
        let error = select_for(&catalog, "node", &engines(">=26"))
            .unwrap_err()
            .to_string();
        assert!(error.contains("node toolchain"), "{error}");
        assert!(error.contains(">=26"), "{error}");
    }

    #[test]
    fn node_engines_disjunctions_take_the_newest_release_any_alternative_admits() {
        let engines = |text: &str| vec![row("package.json", "engines.node", Some(text))];
        // vitejs/vite's range.
        assert_eq!(
            request("node", &engines("^20.19.0 || >=22.12.0")),
            "node >=20.19.0 <21 || >=22.12.0"
        );
        assert_eq!(
            request("node", &engines(">=18.1 <19 || 22.x||=24.2.0")),
            "node >=18.1 <19 || >=22 <23 || ==24.2.0"
        );
        // An unconstrained alternative admits every release.
        for text in ["^20 || *", "^20 ||", "|| ^20"] {
            assert_eq!(request("node", &engines(text)), "newest", "{text}");
        }

        let catalog = catalog("node", "node", &["20.19.5", "21.7.0", "22.11.0", "22.20.0"]);
        let pick = |text: &str| {
            select_for(&catalog, "node", &engines(text))
                .map(|bundle| bundle.release.clone())
                .map_err(|error| error.to_string())
        };
        assert_eq!(pick("^20.19.0 || >=22.12.0").unwrap(), "node-22.20.0");
        // The highest release in any alternative, not the first alternative.
        assert_eq!(pick(">=22.12.0 || ^20.19.0").unwrap(), "node-22.20.0");
        assert_eq!(pick("^20.19.0 || >=23").unwrap(), "node-20.19.5");
        // 21.x and 22.11 fall between the alternatives.
        assert_eq!(pick("^20.20 || ~22.11").unwrap(), "node-22.11.0");
        let error = pick("^19 || >=23").unwrap_err();
        assert!(error.contains("node >=19 <20 || >=23"), "{error}");

        // The pin still intersects with the whole disjunction.
        let rows = vec![
            row(".node-version", "version", Some("20")),
            row(
                "package.json",
                "engines.node",
                Some("^20.19.0 || >=22.12.0"),
            ),
        ];
        assert_eq!(
            select_for(&catalog, "node", &rows).unwrap().release,
            "node-20.19.5"
        );
        let rows = vec![
            row(".node-version", "version", Some("21.7.0")),
            row(
                "package.json",
                "engines.node",
                Some("^20.19.0 || >=22.12.0"),
            ),
        ];
        assert!(select_for(&catalog, "node", &rows).is_err());
    }

    #[test]
    fn node_engines_read_greater_than_at_most_and_hyphen_ranges_like_node_semver() {
        let engines = |text: &str| vec![row("package.json", "engines.node", Some(text))];
        // `>X` is past everything X spells; `<=X` admits everything X spells.
        assert_eq!(request("node", &engines(">24.2.1")), "node >=24.2.2");
        assert_eq!(request("node", &engines(">24.2")), "node >=24.3");
        assert_eq!(request("node", &engines(">24")), "node >=25");
        assert_eq!(request("node", &engines("<=24.2.1")), "node <24.2.2");
        assert_eq!(request("node", &engines("<=24")), "node <25");
        // A partial low end is zero-filled; a partial high end keeps its line.
        assert_eq!(
            request("node", &engines("1.2.3 - 2.3.4")),
            "node >=1.2.3; node <2.3.5"
        );
        assert_eq!(
            request("node", &engines("1.2 - 2.3")),
            "node >=1.2; node <2.4"
        );
        assert_eq!(request("node", &engines("20 - 22")), "node >=20; node <23");
        // An operator spelled apart from its version is one term.
        assert_eq!(
            request("node", &engines(">= 20 < 23")),
            "node >=20; node <23"
        );
        assert_eq!(
            request("node", &engines("18 - 20 || > 22")),
            "node >=18 <21 || >=23"
        );

        let catalog = catalog("node", "node", &["20.19.5", "22.11.0", "22.20.0", "24.1.0"]);
        let pick = |text: &str| {
            select_for(&catalog, "node", &engines(text))
                .unwrap()
                .release
                .clone()
        };
        assert_eq!(pick(">22.11.0"), "node-24.1.0");
        assert_eq!(pick("<=22.11.0"), "node-22.11.0");
        assert_eq!(pick("<=22"), "node-22.20.0");
        assert_eq!(pick("20 - 22.11"), "node-22.11.0");
        assert_eq!(pick("20.0.0 - 22.11.0"), "node-22.11.0");
        assert_eq!(pick("20 - 22"), "node-22.20.0");
        assert_eq!(pick(">22 || <=20"), "node-24.1.0");
    }

    /// Node semver's own reading, case by case: (range, version, satisfies).
    /// The cases follow node-semver's documented range grammar
    /// (X-ranges, partials, caret, tilde, hyphen, primitive comparators).
    #[test]
    fn node_engines_agree_with_node_semver_on_each_case() {
        const CASES: &[(&str, &str, bool)] = &[
            // Bare and `=` partials are X-ranges; three components are exact.
            ("24", "24.0.0", true),
            ("24", "24.20.0", true),
            ("24", "25.0.0", false),
            ("=24", "24.20.0", true),
            ("24.1", "24.1.9", true),
            ("24.1", "24.2.0", false),
            ("24.1.2", "24.1.2", true),
            ("24.1.2", "24.1.3", false),
            ("v24.1.2", "24.1.2", true),
            // Zero-bearing X-ranges keep every stated component.
            ("24.0.x", "24.0.5", true),
            ("24.0.x", "24.20.0", false),
            ("24.0", "24.20.0", false),
            ("0.x", "0.9.0", true),
            ("0.x", "1.0.0", false),
            ("*", "1.0.0", true),
            ("x", "24.0.0", true),
            ("24.x.x", "24.3.1", true),
            ("24.X", "24.3.1", true),
            ("24.*", "25.0.0", false),
            // Primitive comparators over partials.
            (">24", "24.9.9", false),
            (">24", "25.0.0", true),
            (">24.1", "24.1.9", false),
            (">24.1", "24.2.0", true),
            (">24.1.2", "24.1.3", true),
            (">24.1.2", "24.1.2", false),
            (">=24.1", "24.1.0", true),
            (">=24.1", "24.0.9", false),
            ("<24.1", "24.0.9", true),
            ("<24.1", "24.1.0", false),
            ("<=24.1", "24.1.9", true),
            ("<=24.1", "24.2.0", false),
            ("<=24", "24.99.0", true),
            ("<=24.1.2", "24.1.2", true),
            ("<=24.1.2", "24.1.3", false),
            // Caret: the first non-zero stated component is fixed.
            ("^1.2.3", "1.9.0", true),
            ("^1.2.3", "2.0.0", false),
            ("^1.2.3", "1.2.2", false),
            ("^0.2.3", "0.2.9", true),
            ("^0.2.3", "0.3.0", false),
            ("^0.0.3", "0.0.3", true),
            ("^0.0.3", "0.0.4", false),
            ("^0.0", "0.0.9", true),
            ("^0.0", "0.1.0", false),
            ("^0", "0.9.0", true),
            ("^0", "1.0.0", false),
            ("^1.x", "1.9.9", true),
            ("^1.x", "2.0.0", false),
            ("^0.x", "0.9.0", true),
            // Tilde: the minor is fixed when stated, else the major.
            ("~1.2.3", "1.2.9", true),
            ("~1.2.3", "1.3.0", false),
            ("~1.2", "1.2.0", true),
            ("~1.2", "1.3.0", false),
            ("~1", "1.9.0", true),
            ("~1", "2.0.0", false),
            ("~0.2", "0.2.5", true),
            ("~0.2", "0.3.0", false),
            // Hyphen ranges: partial low zero-filled, partial high its line.
            ("1.2.3 - 2.3.4", "2.3.4", true),
            ("1.2.3 - 2.3.4", "2.3.5", false),
            ("1.2.3 - 2.3.4", "1.2.2", false),
            ("1.2 - 2.3.4", "1.2.0", true),
            ("1.2.3 - 2.3", "2.3.9", true),
            ("1.2.3 - 2.3", "2.4.0", false),
            ("1.2.3 - 2", "2.9.9", true),
            ("1.2.3 - 2", "3.0.0", false),
            ("1.x - 2.x", "2.9.0", true),
            ("* - 2", "0.1.0", true),
            ("24.0 - 24.0", "24.0.9", true),
            ("24.0 - 24.0", "24.1.0", false),
            // Sets and disjunctions.
            (">=1.2.7 <1.3.0", "1.2.8", true),
            (">=1.2.7 <1.3.0", "1.3.0", false),
            (">= 1.2.7 < 1.3.0", "1.2.7", true),
            ("1.2.7 || >=1.2.9 <2.0.0", "1.2.8", false),
            ("1.2.7 || >=1.2.9 <2.0.0", "1.4.6", true),
            ("24 || 26", "24.20.0", true),
            ("24 || 26", "25.0.0", false),
            ("24.0.x || 22.20.x", "24.20.0", false),
            ("24.0.x || 22.20.x", "22.20.1", true),
        ];
        for (range, version, satisfies) in CASES {
            let terms = engines_node(range).unwrap_or_else(|e| panic!("{range}: {e}"));
            let candidate = Version::parse(version).unwrap();
            let admitted = terms.iter().all(|term| term.matches(&candidate));
            assert_eq!(admitted, *satisfies, "{range} vs {version}");
        }
    }

    /// Zero-bearing and bare partials select from a real-shaped catalog:
    /// `24.0.x` does not widen to 24.x, and `24 || 26` is a line, not 24.0.0.
    #[test]
    fn node_partials_select_their_whole_line_and_no_wider() {
        let engines = |text: &str| vec![row("package.json", "engines.node", Some(text))];
        let catalog = catalog(
            "node",
            "node",
            &["22.20.0", "22.20.3", "24.0.2", "24.20.0", "25.1.0"],
        );
        let pick = |text: &str| {
            select_for(&catalog, "node", &engines(text))
                .map(|bundle| bundle.release.clone())
                .map_err(|error| error.to_string())
        };
        assert_eq!(pick("24.0.x || 22.20.x").unwrap(), "node-24.0.2");
        assert_eq!(pick("24.0").unwrap(), "node-24.0.2");
        assert_eq!(pick("24 || 26").unwrap(), "node-24.20.0");
        assert_eq!(pick("=24").unwrap(), "node-24.20.0");
        assert_eq!(pick("22.20").unwrap(), "node-22.20.3");
        assert!(pick("24.1").is_err());
        // `.node-version 24.0` is the 24.0 line too.
        let pin = vec![row(".node-version", "version", Some("24.0"))];
        assert_eq!(
            select_for(&catalog, "node", &pin).unwrap().release,
            "node-24.0.2"
        );
    }

    #[test]
    fn node_engines_read_the_kernel_grammar_like_node_semver() {
        // Spellings node-semver 7.8.5 accepts: `~>` is tilde, and a `[v=]*`
        // prefix may sit before a partial or after `^`/`~`.
        let line = |low: &str, high: &str| {
            format!(
                "[Specifiers([Specifier {{ op: Ge, version: Version([{low}]) }}]), \
                 Specifiers([Specifier {{ op: Lt, version: Version([{high}]) }}])]"
            )
        };
        for (text, low, high) in [
            ("~>24.2", "24, 2", "24, 3"),
            ("~> 24.2", "24, 2", "24, 3"),
            ("==24", "24", "25"),
            ("v=24", "24", "25"),
            ("vv24", "24", "25"),
            ("^=24", "24", "25"),
            ("==1.2", "1, 2", "1, 3"),
        ] {
            assert_eq!(
                format!("{:?}", engines_node(text).unwrap()),
                line(low, high),
                "{text}"
            );
        }
        // Spellings node-semver 7.8.5 refuses: `==` before a full version,
        // and a hyphen range mixed with other comparators.
        for text in ["==1.2.3", "1 - 2 >=1.5", ">=1.5 1 - 2"] {
            assert!(engines_node(text).is_err(), "{text}");
        }
    }

    #[test]
    fn node_partials_refuse_overflow_and_out_of_range_components() {
        // Past node semver's Number.MAX_SAFE_INTEGER, and u64::MAX, refuse
        // rather than overflow while bumping.
        for text in [
            "9007199254740992",
            "<=18446744073709551615",
            ">1.18446744073709551615",
        ] {
            assert!(engines_node(text).is_err(), "{text}");
        }
        // A generated bound past the limit is refused, as node semver
        // refuses the range: partials, caret, tilde, a partial hyphen end.
        for text in [
            "9007199254740991",
            "=9007199254740991",
            "<=9007199254740991",
            ">9007199254740991",
            "24.9007199254740991",
            "^0.9007199254740991",
            "~1.9007199254740991",
            "1 - 9007199254740991",
        ] {
            assert!(engines_node(text).is_err(), "{text}");
        }
        // Full three-component `>` and `<=` stay comparators on the version
        // itself, and so does a full hyphen end.
        for text in [
            "<=1.2.9007199254740991",
            ">1.2.9007199254740991",
            "1.0.0 - 1.2.9007199254740991",
            "^1.2.9007199254740991",
            "9007199254740991.0.0",
        ] {
            assert!(engines_node(text).is_ok(), "{text}");
        }
    }

    #[test]
    fn rust_takes_an_exact_channel_or_stable_and_nothing_else() {
        let legacy = |text: &str| vec![row("rust-toolchain", "toolchain.channel", Some(text))];
        let modern = |text: &str| vec![row("rust-toolchain.toml", "toolchain.channel", Some(text))];
        assert_eq!(request("rust", &legacy("1.96.1")), "rustc ==1.96.1");
        assert_eq!(request("rust", &modern("1.96.1")), "rustc ==1.96.1");
        assert_eq!(request("rust", &modern("stable")), "newest");
        for channel in ["nightly", "beta", "nightly-2026-01-01", "1.96.1-x86_64"] {
            let error = refusal("rust", &modern(channel));
            assert!(
                error.contains(&format!("rust channel {channel} is not supported")),
                "{channel}: {error}"
            );
            assert!(
                error.contains("use an exact version or stable"),
                "{channel}: {error}"
            );
        }
        // Two files that disagree are a conflict, not a precedence question.
        let both = vec![
            row("rust-toolchain", "toolchain.channel", Some("1.96.1")),
            row("rust-toolchain.toml", "toolchain.channel", Some("1.95.0")),
        ];
        let error = refusal("rust", &both);
        assert!(error.contains("make them agree"), "{error}");
        let agreeing = vec![
            row("rust-toolchain", "toolchain.channel", Some("1.96.1")),
            row("rust-toolchain.toml", "toolchain.channel", Some("1.96.1")),
        ];
        assert_eq!(request("rust", &agreeing), "rustc ==1.96.1");
    }

    #[test]
    fn go_treats_the_directive_as_a_minimum_and_the_toolchain_as_exact() {
        let minimum = vec![row("go.mod", "go", Some("1.22"))];
        assert_eq!(request("go", &minimum), "go >=1.22");
        let exact = vec![
            row("go.mod", "go", Some("1.22")),
            row("go.mod", "toolchain", Some("1.24.2")),
        ];
        assert_eq!(request("go", &exact), "go ==1.24.2");
        // With a newer row present, the exact toolchain still wins.
        let catalog = catalog("go", "go", &["1.22.0", "1.24.2", "1.25.0"]);
        assert_eq!(
            select_for(&catalog, "go", &exact).unwrap().release,
            "go-1.24.2"
        );
        assert_eq!(
            select_for(&catalog, "go", &minimum).unwrap().release,
            "go-1.25.0"
        );
        let below = vec![
            row("go.mod", "go", Some("1.25")),
            row("go.mod", "toolchain", Some("1.24.2")),
        ];
        let error = refusal("go", &below);
        assert!(
            error.contains("does not satisfy the go 1.25 minimum"),
            "{error}"
        );
    }

    #[test]
    fn ruby_reads_two_sources_that_must_agree() {
        assert_eq!(
            request("ruby", &[row(".ruby-version", "version", Some("3.3.0"))]),
            "ruby ==3.3.0"
        );
        assert_eq!(
            request("ruby", &[row(".tool-versions", "ruby", Some("3.3"))]),
            "ruby 3.3.*"
        );
        let conflict = vec![
            row(".ruby-version", "version", Some("3.3.0")),
            row(".tool-versions", "ruby", Some("3.2.0")),
        ];
        let error = refusal("ruby", &conflict);
        assert!(error.contains("make them agree"), "{error}");
    }

    #[test]
    fn elixir_asks_for_the_otp_and_elixir_pair() {
        let rows = vec![
            row(".tool-versions", "erlang", Some("27.3.4")),
            row(".tool-versions", "elixir", Some("1.18.4-otp-27")),
        ];
        assert_eq!(request("elixir", &rows), "otp ==27.3.4; elixir ==1.18.4");
        let loose = vec![
            row(".tool-versions", "erlang", Some("27")),
            row(".tool-versions", "elixir", Some("1.18")),
        ];
        assert_eq!(request("elixir", &loose), "otp 27.*; elixir 1.18.*");
    }

    #[test]
    fn dotnet_needs_roll_forward_disabled_for_an_exact_sdk() {
        let rows = vec![
            row("global.json", "sdk.version", Some("9.0.317")),
            row("global.json", "sdk.rollForward", Some("disable")),
        ];
        assert_eq!(request("dotnet", &rows), "dotnet-sdk ==9.0.317");
        for roll in [None, Some("latestPatch")] {
            let rows = vec![
                row("global.json", "sdk.version", Some("9.0.317")),
                row("global.json", "sdk.rollForward", roll),
            ];
            let error = refusal("dotnet", &rows);
            assert!(
                error.contains("sdk.rollForward must be \"disable\""),
                "{roll:?}: {error}"
            );
        }
        assert_eq!(
            request(
                "dotnet",
                &[
                    row("global.json", "sdk.version", None),
                    row("global.json", "sdk.rollForward", None)
                ]
            ),
            "newest"
        );
    }
}

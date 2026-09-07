//! `add`, `remove`, `update` (CLI.md 2.3).
//!
//! Doctrine: resolution belongs to the ecosystem's pinned tool, realization
//! belongs to blanket. Every manifest or lock edit below is delegated to a
//! store tool (uv, the store node's npm, pinned pnpm, cargo, go, bundler, mix)
//! running unsandboxed with network — the same trust boundary as
//! missing-lockfile generation. Where no pinned tool can make the edit,
//! blanket **refuses with the exact line and file**; that is still one tool
//! telling the user what to type next. Blanket edits a file itself in exactly
//! one case: a plain requirements file, where the "tool" is a text append.
//!
//! Choosing the ecosystem is the evidence ladder (CLI.md decision 3): an
//! explicit prefix, the name's shape, the nearest manifest, the registries,
//! then the human. Never a coin flip.

use std::fs;
use std::fs::OpenOptions;
use std::io::{self, BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

use crate::platform::Platform;
use crate::store::Store;
use crate::{
    cargo, elixir, golang, inspect, manifest, npm, pypi, pyselect, python, ruby, sandbox, ui, xrun,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verb {
    Add,
    Remove,
    Update,
}

impl Verb {
    fn past(self) -> &'static str {
        match self {
            Verb::Add => "added",
            Verb::Remove => "removed",
            Verb::Update => "updated",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Eco {
    Python,
    Node,
    Cargo,
    Go,
    Ruby,
    Elixir,
    Dotnet,
}

impl Eco {
    pub const ALL: [Eco; 7] = [
        Eco::Python,
        Eco::Node,
        Eco::Cargo,
        Eco::Go,
        Eco::Ruby,
        Eco::Elixir,
        Eco::Dotnet,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Eco::Python => "python",
            Eco::Node => "node",
            Eco::Cargo => "cargo",
            Eco::Go => "go",
            Eco::Ruby => "ruby",
            Eco::Elixir => "elixir",
            Eco::Dotnet => "dotnet",
        }
    }

    /// The explicit spelling: `npm:react`, `py:requests`, ...
    pub fn prefix(self) -> &'static str {
        match self {
            Eco::Python => "py",
            Eco::Node => "npm",
            Eco::Cargo => "cargo",
            Eco::Go => "go",
            Eco::Ruby => "gem",
            Eco::Elixir => "hex",
            Eco::Dotnet => "nuget",
        }
    }

    pub fn registry(self) -> &'static str {
        match self {
            Eco::Python => "PyPI",
            Eco::Node => "npm",
            Eco::Cargo => "crates.io",
            Eco::Go => "the Go module proxy",
            Eco::Ruby => "RubyGems",
            Eco::Elixir => "Hex",
            Eco::Dotnet => "NuGet",
        }
    }

    fn from_name(name: &str) -> Option<Eco> {
        Eco::ALL.into_iter().find(|eco| eco.name() == name)
    }

    fn from_prefix(prefix: &str) -> Option<Eco> {
        Eco::ALL.into_iter().find(|eco| eco.prefix() == prefix)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub verb: Verb,
    pub specs: Vec<String>,
    pub dev: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    /// The project directory the edit was made in (the nearest project
    /// from the working directory upward); `sync` runs there next.
    pub project: PathBuf,
    /// One human line per ecosystem touched.
    pub lines: Vec<String>,
}

/// One requested package: the text the tool receives, the bare name for
/// lookups, and the ecosystem if the spelling already decided it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Spec {
    pub text: String,
    pub name: String,
    pub eco: Option<Eco>,
}

fn other(message: impl Into<String>) -> io::Error {
    io::Error::other(message.into())
}

/// Validate the untrusted spelling supplied on the command line before it is
/// used for registry lookups or passed to an ecosystem tool.
///
/// Explicit ecosystem prefixes are intentionally checked after they are
/// removed as well: `npm:--prefix=/tmp` must be rejected just like the
/// unprefixed spelling.  Keep this separate from `parse_spec`, whose return
/// type is part of the small public parsing API and cannot report an error.
pub fn validate_spec(text: &str) -> io::Result<()> {
    if text.is_empty() || text.trim().is_empty() {
        return Err(other("dependency spec must not be empty"));
    }
    if text != text.trim() {
        return Err(other(
            "dependency spec must not begin or end with whitespace",
        ));
    }
    if text.bytes().any(|byte| matches!(byte, b'\r' | b'\n' | 0)) {
        return Err(other("dependency spec must not contain CR, LF, or NUL"));
    }

    let candidate = match text.split_once(':') {
        Some((prefix, rest)) if Eco::from_prefix(prefix).is_some() => rest,
        _ => text,
    };
    if candidate.trim().is_empty() {
        return Err(other("dependency spec must name a package"));
    }
    if candidate != candidate.trim() {
        return Err(other(
            "dependency spec must not begin or end with whitespace",
        ));
    }
    if candidate.trim_start().starts_with('-') {
        return Err(other(format!(
            "dependency spec '{text}' looks like a tool option; package options are not allowed"
        )));
    }
    if candidate
        .split(|character: char| "@><=~![;,".contains(character))
        .any(|part| part.trim_start().starts_with('-'))
    {
        return Err(other(format!(
            "dependency spec '{text}' contains an option-shaped constraint"
        )));
    }

    let parsed = parse_spec(text);
    if parsed.name.is_empty() {
        return Err(other(format!(
            "dependency spec '{text}' must name a package"
        )));
    }
    Ok(())
}

fn validate_parsed_spec(spec: &Spec) -> io::Result<()> {
    validate_spec(&spec.text)?;
    if spec.name.is_empty() || spec.name.trim_start().starts_with('-') {
        return Err(other("dependency spec must name a package"));
    }
    Ok(())
}

fn validate_delegate_specs(texts: &[String]) -> io::Result<()> {
    for text in texts {
        validate_spec(text)?;
    }
    Ok(())
}

/// Rung 1: an explicit `prefix:`. The name is the spec up to the first
/// version operator (`@` after the first character, `>`, `<`, `=`, `~`,
/// `!`, `[`, `;`, or a space).
pub fn parse_spec(text: &str) -> Spec {
    let (eco, rest) = match text.split_once(':') {
        Some((prefix, rest)) if !rest.is_empty() && !prefix.is_empty() => {
            match Eco::from_prefix(prefix) {
                Some(eco) => (Some(eco), rest),
                None => (None, text),
            }
        }
        _ => (None, text),
    };
    let scoped = rest.starts_with('@');
    let body = if scoped { &rest[1..] } else { rest };
    let end = body
        .find(|c: char| "@><=~![; ".contains(c))
        .unwrap_or(body.len());
    let name = if scoped {
        format!("@{}", &body[..end])
    } else {
        body[..end].to_string()
    };
    Spec {
        text: rest.to_string(),
        name,
        eco,
    }
}

/// Rung 2: names whose shape fixes the ecosystem.
pub fn shape(name: &str) -> Option<Eco> {
    if name.starts_with('@') && name.contains('/') {
        return Some(Eco::Node);
    }
    if let Some((host, _)) = name.split_once('/') {
        if host.contains('.') && !host.starts_with('.') {
            return Some(Eco::Go);
        }
    }
    if name.contains('.')
        && name
            .split('.')
            .all(|part| part.chars().next().is_some_and(|c| c.is_ascii_uppercase()))
    {
        return Some(Eco::Dotnet);
    }
    None
}

/// The nearest directory from `cwd` upward that holds any project input.
pub fn nearest_project(cwd: &Path) -> io::Result<(PathBuf, Vec<Eco>)> {
    for dir in cwd.ancestors() {
        let present: Vec<Eco> = inspect::detected(dir)?
            .into_iter()
            .filter_map(Eco::from_name)
            .collect();
        if !present.is_empty() {
            return Ok((dir.to_path_buf(), present));
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!(
            "no project from {} upward (looked for requirements.txt, pyproject.toml, package.json, Cargo.toml, go.mod, Gemfile, mix.exs, *.csproj)",
            cwd.display()
        ),
    ))
}

fn require_present(eco: Eco, name: &str, present: &[Eco], how: &str) -> io::Result<Eco> {
    if present.contains(&eco) {
        return Ok(eco);
    }
    Err(other(format!(
        "'{name}' is a {} package ({how}), but this project has no {} manifest (found: {})",
        eco.registry(),
        eco.name(),
        present
            .iter()
            .map(|eco| eco.name())
            .collect::<Vec<_>>()
            .join(", ")
    )))
}

/// Rungs 1–5 for one spec. `lookup` is the registry probe (injected so the
/// ladder is testable without network) and `ask` the human prompt.
pub fn choose(
    spec: &Spec,
    present: &[Eco],
    lookup: &mut dyn FnMut(Eco, &str) -> io::Result<Option<String>>,
    ask: &mut dyn FnMut(&str, &[(Eco, String)]) -> io::Result<Eco>,
) -> io::Result<Eco> {
    validate_parsed_spec(spec)?;
    if let Some(eco) = spec.eco {
        return require_present(eco, &spec.name, present, "you said so");
    }
    if let Some(eco) = shape(&spec.name) {
        return require_present(eco, &spec.name, present, "by its shape");
    }
    if let [only] = present {
        return Ok(*only);
    }
    let mut known = Vec::new();
    for eco in present {
        if let Some(version) = lookup(*eco, &spec.name)? {
            known.push((*eco, version));
        }
    }
    match known.as_slice() {
        [(eco, _)] => Ok(*eco),
        [] => Err(other(format!(
            "'{}' is not on {}; if it is private or local, say which ecosystem: {}",
            spec.name,
            present
                .iter()
                .map(|eco| eco.registry())
                .collect::<Vec<_>>()
                .join(" or "),
            present
                .iter()
                .map(|eco| format!("{}:{}", eco.prefix(), spec.text))
                .collect::<Vec<_>>()
                .join(" / ")
        ))),
        _ => ask(&spec.name, &known),
    }
}

fn get_json(url: &str) -> io::Result<Option<serde_json::Value>> {
    let agent = ureq::AgentBuilder::new()
        .https_only(true)
        .timeout(std::time::Duration::from_secs(20))
        .user_agent("blanket (https://github.com/DigitalWestern/blanket)")
        .build();
    match agent.get(url).call() {
        Ok(response) => {
            let text = response.into_string()?;
            serde_json::from_str(&text)
                .map(Some)
                .map_err(|error| other(format!("GET {url}: not JSON: {error}")))
        }
        Err(ureq::Error::Status(404, _)) => Ok(None),
        Err(ureq::Error::Status(code, _)) => Err(other(format!("GET {url}: HTTP {code}"))),
        Err(error) => Err(other(format!("GET {url}: {error}"))),
    }
}

/// Rung 3: does the registry know this name? `Some(latest version)`.
pub fn registry_lookup(eco: Eco, name: &str) -> io::Result<Option<String>> {
    let lower = name.to_ascii_lowercase();
    let (url, extract): (String, fn(&serde_json::Value) -> Option<String>) = match eco {
        Eco::Python => (format!("https://pypi.org/pypi/{name}/json"), |v| {
            v["info"]["version"].as_str().map(str::to_string)
        }),
        Eco::Node => (format!("https://registry.npmjs.org/{name}"), |v| {
            v["dist-tags"]["latest"].as_str().map(str::to_string)
        }),
        Eco::Cargo => (format!("https://crates.io/api/v1/crates/{name}"), |v| {
            v["crate"]["max_stable_version"]
                .as_str()
                .or_else(|| v["crate"]["max_version"].as_str())
                .map(str::to_string)
        }),
        Eco::Go => (format!("https://proxy.golang.org/{lower}/@latest"), |v| {
            v["Version"].as_str().map(str::to_string)
        }),
        Eco::Ruby => (
            format!("https://rubygems.org/api/v1/gems/{name}.json"),
            |v| v["version"].as_str().map(str::to_string),
        ),
        Eco::Elixir => (format!("https://hex.pm/api/packages/{name}"), |v| {
            v["latest_stable_version"]
                .as_str()
                .or_else(|| v["latest_version"].as_str())
                .map(str::to_string)
        }),
        Eco::Dotnet => (
            format!("https://api.nuget.org/v3-flatcontainer/{lower}/index.json"),
            |v| {
                v["versions"]
                    .as_array()
                    .and_then(|versions| versions.last())
                    .and_then(|version| version.as_str())
                    .map(str::to_string)
            },
        ),
    };
    ui::trace(&format!("asking {} about '{name}': {url}", eco.registry()));
    let value = get_json(&url).map_err(|error| {
        other(format!(
            "could not ask {} whether '{name}' exists ({error}); say which ecosystem: {}:{name}",
            eco.registry(),
            eco.prefix()
        ))
    })?;
    Ok(value.and_then(|value| extract(&value).or_else(|| Some("?".to_string()))))
}

/// Rung 4/5: the human, or an error when there is no terminal.
pub fn ask_human(name: &str, known: &[(Eco, String)]) -> io::Result<Eco> {
    let described = known
        .iter()
        .map(|(eco, version)| format!("{} ({version})", eco.registry()))
        .collect::<Vec<_>>();
    let spellings = known
        .iter()
        .map(|(eco, _)| format!("{}:{name}", eco.prefix()))
        .collect::<Vec<_>>();
    if !(io::stderr().is_terminal() && io::stdin().is_terminal()) {
        return Err(other(format!(
            "'{name}' exists on {}; not a terminal, so say which: {}",
            described.join(" and "),
            spellings.join(" or ")
        )));
    }
    let mut stderr = io::stderr();
    writeln!(
        stderr,
        "blanket: '{name}' exists on {}. Which one?",
        described.join(" and ")
    )?;
    for (index, (eco, version)) in known.iter().enumerate() {
        writeln!(
            stderr,
            "  {}) {}:{name}  ({} {version})",
            index + 1,
            eco.prefix(),
            eco.registry()
        )?;
    }
    let stdin = io::stdin();
    loop {
        write!(stderr, "blanket: [1-{}] ", known.len())?;
        stderr.flush()?;
        let mut line = String::new();
        if stdin.lock().read_line(&mut line)? == 0 {
            return Err(other("no answer; nothing changed"));
        }
        let answer = line.trim();
        if let Ok(index) = answer.parse::<usize>() {
            if (1..=known.len()).contains(&index) {
                return Ok(known[index - 1].0);
            }
        }
        if let Some((eco, _)) = known
            .iter()
            .find(|(eco, _)| eco.prefix() == answer || eco.name() == answer)
        {
            return Ok(*eco);
        }
    }
}

/// Entry point for `main`: pick the project, group the specs by ecosystem,
/// delegate each group.
pub fn run(platform: Platform, cwd: &Path, request: Request) -> io::Result<Outcome> {
    // Validate every spec before discovering the project, opening the store,
    // looking anything up in a registry, or invoking a package manager.
    for text in &request.specs {
        validate_spec(text)?;
    }
    let (project, present) = nearest_project(cwd)?;
    if project != cwd {
        ui::note(&format!("project: {}", project.display()));
    }
    let store = Store::open()?;
    let mut groups: Vec<(Eco, Vec<Spec>)> = Vec::new();
    if request.specs.is_empty() {
        // `update` with nothing named: every ecosystem present.
        for eco in &present {
            groups.push((*eco, Vec::new()));
        }
    }
    for text in &request.specs {
        let spec = parse_spec(text);
        let eco = choose(&spec, &present, &mut registry_lookup, &mut ask_human)?;
        match groups.iter_mut().find(|(known, _)| *known == eco) {
            Some((_, specs)) => specs.push(spec),
            None => groups.push((eco, vec![spec])),
        }
    }
    let mut lines = Vec::new();
    let mut outcome_project = project.clone();
    for (eco, specs) in groups {
        let names: Vec<String> = specs.iter().map(|spec| spec.name.clone()).collect();
        let texts: Vec<String> = specs.iter().map(|spec| spec.text.clone()).collect();
        let files = match eco {
            Eco::Python => python(
                &store,
                platform,
                &project,
                request.verb,
                &texts,
                &names,
                request.dev,
            )?,
            Eco::Node => {
                let outcome = node(
                    &store,
                    platform,
                    &project,
                    request.verb,
                    &texts,
                    request.dev,
                )?;
                outcome_project = outcome.sync_project;
                outcome.files
            }
            Eco::Cargo => cargo_delegate(
                &store,
                platform,
                &project,
                request.verb,
                &texts,
                request.dev,
            )?,
            Eco::Go => go_delegate(
                &store,
                platform,
                &project,
                request.verb,
                &texts,
                request.dev,
            )?,
            Eco::Ruby => ruby_delegate(
                &store,
                platform,
                &project,
                request.verb,
                &texts,
                request.dev,
            )?,
            Eco::Elixir => elixir_delegate(&store, platform, &project, request.verb, &texts)?,
            Eco::Dotnet => dotnet_refuse(request.verb, &texts)?,
        };
        let what = if names.is_empty() {
            "everything".to_string()
        } else {
            names.join(", ")
        };
        lines.push(format!(
            "{}: {} {what}",
            files.join(", "),
            request.verb.past()
        ));
    }
    Ok(Outcome {
        project: outcome_project,
        lines,
    })
}

// ---------------------------------------------------------------------------
// Python

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PyShape {
    /// `pyproject.toml` with `[project]` and no foreign lock: uv edits it.
    Uv,
    Poetry,
    Pdm,
    /// `requirements.in` compiled into `requirements.txt` (pip-tools / uv
    /// convention): blanket edits the .in and recompiles.
    PipCompile,
    /// A plain requirements file blanket re-locks into requirements.lock.txt.
    Requirements(PathBuf),
    Setup,
    RequirementsDir,
}

pub fn python_shape(project: &Path) -> io::Result<PyShape> {
    let has = |name: &str| project.join(name).is_file();
    if has("requirements.in") && has("requirements.txt") {
        return Ok(PyShape::PipCompile);
    }
    if has("requirements.txt") {
        return Ok(PyShape::Requirements(project.join("requirements.txt")));
    }
    if has("pyproject.toml") {
        let text = fs::read_to_string(project.join("pyproject.toml"))?;
        let value: toml::Table = text
            .parse()
            .map_err(|error| other(format!("pyproject.toml: {error}")))?;
        let tool = value.get("tool").and_then(toml::Value::as_table);
        if has("poetry.lock") || tool.is_some_and(|tool| tool.contains_key("poetry")) {
            return Ok(PyShape::Poetry);
        }
        if has("pdm.lock") {
            return Ok(PyShape::Pdm);
        }
        if value.get("project").is_some() {
            return Ok(PyShape::Uv);
        }
    }
    if has("setup.cfg") || has("setup.py") {
        return Ok(PyShape::Setup);
    }
    if project.join("requirements").is_dir() {
        return Ok(PyShape::RequirementsDir);
    }
    Err(other("no Python manifest here"))
}

fn python_line(texts: &[String]) -> String {
    texts
        .iter()
        .map(|text| format!("\"{text}\""))
        .collect::<Vec<_>>()
        .join(", ")
}

fn python(
    store: &Store,
    platform: Platform,
    project: &Path,
    verb: Verb,
    texts: &[String],
    names: &[String],
    dev: bool,
) -> io::Result<Vec<String>> {
    validate_delegate_specs(texts)?;
    let shape = python_shape(project)?;
    match shape {
        PyShape::Poetry => Err(other(match verb {
            Verb::Add => format!(
                "this is a Poetry project and Poetry is not a pinned tool: add {} under [tool.poetry.dependencies] in pyproject.toml (or run 'poetry add {}'), then 'blanket'",
                python_line(texts),
                texts.join(" ")
            ),
            Verb::Remove => format!(
                "this is a Poetry project: remove {} from [tool.poetry.dependencies] in pyproject.toml (or run 'poetry remove {}'), then 'blanket'",
                names.join(", "),
                names.join(" ")
            ),
            Verb::Update => "this is a Poetry project: run 'poetry update' (or 'poetry lock'), then 'blanket'".to_string(),
        })),
        PyShape::Pdm => Err(other(format!(
            "this is a PDM project (pdm.lock) and PDM is not a pinned tool: run 'pdm {} {}', then 'blanket'",
            match verb {
                Verb::Add => "add",
                Verb::Remove => "remove",
                Verb::Update => "update",
            },
            texts.join(" ")
        ))),
        PyShape::Setup => Err(other(match verb {
            Verb::Add => format!(
                "dependencies live in install_requires here: add {} to setup.cfg [options] install_requires (or setup.py), then 'blanket'",
                python_line(texts)
            ),
            Verb::Remove => format!(
                "dependencies live in install_requires here: remove {} from setup.cfg / setup.py, then 'blanket'",
                names.join(", ")
            ),
            Verb::Update => "install_requires projects re-lock on every 'blanket sync' (there is no separate lock to update); loosen the constraint in setup.cfg / setup.py, then 'blanket'".to_string(),
        })),
        PyShape::RequirementsDir => Err(other(format!(
            "dependencies live under requirements/ here: edit the file that applies (requirements/common.txt, base.txt, ...) to {} {}, then 'blanket'",
            match verb {
                Verb::Add => "add",
                Verb::Remove => "remove",
                Verb::Update => "update",
            },
            texts.join(" ")
        ))),
        PyShape::Uv => python_uv(store, platform, project, verb, texts, dev),
        PyShape::PipCompile => {
            if dev {
                return Err(other("--dev has no meaning for a requirements file"));
            }
            let input = project.join("requirements.in");
            let output = project.join("requirements.txt");
            match verb {
                Verb::Add => edit_requirements(&input, texts, &[])?,
                Verb::Remove => edit_requirements(&input, &[], names)?,
                Verb::Update => {}
            }
            let upgrade = upgrade_flags(verb, names);
            uv_compile(store, platform, project, &input, &output, &upgrade)?;
            Ok(vec![
                "requirements.in".to_string(),
                "requirements.txt".to_string(),
            ])
        }
        PyShape::Requirements(path) => {
            if dev {
                return Err(other("--dev has no meaning for a requirements file"));
            }
            let file = path
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default();
            match verb {
                Verb::Add => edit_requirements(&path, texts, &[])?,
                Verb::Remove => edit_requirements(&path, &[], names)?,
                Verb::Update => {}
            }
            let lock = project.join("requirements.lock.txt");
            let mut files = vec![file];
            if verb == Verb::Update && lock.is_file() {
                uv_compile(store, platform, project, &path, &lock, &upgrade_flags(verb, names))?;
                files.push("requirements.lock.txt".to_string());
            } else {
                // The ordinary sync re-locks when the source hash changes; a
                // stale stamp from an unchanged source (update with no lock
                // yet) is cleared so sync resolves afresh.
                let stamp = project.join(".blanket/lock-source.hash");
                if stamp.is_file() {
                    fs::remove_file(&stamp)?;
                }
                if verb == Verb::Update {
                    files.push("(re-locks on sync)".to_string());
                }
            }
            Ok(files)
        }
    }
}

fn upgrade_flags(verb: Verb, names: &[String]) -> Vec<String> {
    if verb != Verb::Update {
        return Vec::new();
    }
    if names.is_empty() {
        return vec!["--upgrade".to_string()];
    }
    names
        .iter()
        .flat_map(|name| ["--upgrade-package".to_string(), name.clone()])
        .collect()
}

/// A requirement line's normalized name (`None` for comments, options,
/// blank lines).
pub fn requirement_name(line: &str) -> Option<String> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') || line.starts_with('-') {
        return None;
    }
    let end = line
        .find(|c: char| " [<>=!~;#@\\".contains(c))
        .unwrap_or(line.len());
    let name = &line[..end];
    if name.is_empty() {
        None
    } else {
        Some(pypi::normalize_name(name))
    }
}

/// Add specs (replacing an existing logical record for the same name) and
/// remove names; everything else in the file is preserved byte for byte.
/// Written atomically.
pub fn edit_requirements(path: &Path, add: &[String], remove: &[String]) -> io::Result<()> {
    let text = fs::read_to_string(path)?;

    for value in add.iter().chain(remove) {
        if value.bytes().any(|byte| matches!(byte, b'\r' | b'\n' | 0)) {
            return Err(other(format!(
                "dependency requirement '{value}' must not contain CR, LF, or NUL"
            )));
        }
    }

    #[derive(Debug)]
    struct Record {
        raw: String,
        name: Option<String>,
    }

    fn physical_lines(text: &str) -> Vec<&str> {
        if text.is_empty() {
            return Vec::new();
        }
        text.split_inclusive('\n').collect()
    }

    fn continued(line: &str) -> bool {
        let line = line.strip_suffix('\n').unwrap_or(line);
        let line = line.strip_suffix('\r').unwrap_or(line);
        line.trim_end_matches([' ', '\t']).ends_with('\\')
    }

    // A requirement and its indented `--hash` continuations are one logical
    // record.  Editing only physical lines is what used to leave orphaned
    // hash constraints behind after a remove.
    let physical = physical_lines(&text);
    let mut records = Vec::new();
    let mut index = 0;
    while index < physical.len() {
        let start = index;
        while index + 1 < physical.len() && continued(physical[index]) {
            index += 1;
        }
        index += 1;
        let raw = physical[start..index].concat();
        let name = requirement_name(physical[start]);
        records.push(Record { raw, name });
    }
    let existing_names: Vec<String> = records
        .iter()
        .filter_map(|record| record.name.clone())
        .collect();

    let remove_names: Vec<String> = remove
        .iter()
        .map(|name| pypi::normalize_name(name))
        .collect();
    for (name, wanted) in remove.iter().zip(&remove_names) {
        let matches: Vec<usize> = records
            .iter()
            .enumerate()
            .filter_map(|(index, record)| (record.name.as_deref() == Some(wanted)).then_some(index))
            .collect();
        if matches.is_empty() {
            return Err(other(format!(
                "'{name}' is not declared in {}",
                path.display()
            )));
        }
        if matches.len() > 1 {
            return Err(other(format!(
                "'{name}' is declared {} times in {}; refusing an ambiguous edit",
                matches.len(),
                path.display()
            )));
        }
    }

    let mut additions = Vec::new();
    let mut add_names = Vec::new();
    for spec in add {
        let wanted = requirement_name(spec).ok_or_else(|| {
            other(format!(
                "'{spec}' is not a requirement (name first, e.g. 'requests>=2')"
            ))
        })?;
        if add_names.contains(&wanted) {
            return Err(other(format!(
                "'{spec}' duplicates another requirement in the same edit"
            )));
        }
        let matches = records
            .iter()
            .filter(|record| record.name.as_deref() == Some(&wanted))
            .count();
        if matches > 1 {
            return Err(other(format!(
                "'{spec}' matches {} declarations in {}; refusing an ambiguous edit",
                matches,
                path.display()
            )));
        }
        add_names.push(wanted.clone());
        additions.push((wanted, spec));
    }

    let newline = if text.contains("\r\n") { "\r\n" } else { "\n" };
    let mut out = String::with_capacity(text.len());
    for record in records {
        if record
            .name
            .as_ref()
            .is_some_and(|name| remove_names.contains(name))
        {
            continue;
        }
        if let Some((_, spec)) = additions
            .iter()
            .find(|(wanted, _)| record.name.as_ref() == Some(wanted))
        {
            if requirement_has_marker(&record.raw) != requirement_has_marker(spec) {
                return Err(other(format!(
                    "'{spec}' would change the environment marker on an existing declaration in {}; specify the marker explicitly",
                    path.display()
                )));
            }
            // Keep the original logical record's final line ending, so a
            // no-trailing-newline file stays that way and CRLF files stay
            // CRLF.  Replacing the whole record also removes all old hashes.
            let ending = if record.raw.ends_with("\r\n") {
                "\r\n"
            } else if record.raw.ends_with('\n') {
                "\n"
            } else {
                ""
            };
            out.push_str(spec);
            out.push_str(ending);
        } else {
            out.push_str(&record.raw);
        }
    }

    let unmatched: Vec<&String> = additions
        .iter()
        .filter_map(|(wanted, spec)| (!existing_names.contains(wanted)).then_some(*spec))
        .collect();
    if !unmatched.is_empty() {
        if !out.is_empty() && !out.ends_with(['\n', '\r']) {
            out.push_str(newline);
        }
        for (index, spec) in unmatched.iter().enumerate() {
            out.push_str(spec);
            if text.ends_with(['\n', '\r']) || index + 1 < unmatched.len() {
                out.push_str(newline);
            }
        }
    }

    write_atomic_requirements(path, &out)
}

fn requirement_has_marker(value: &str) -> bool {
    value
        .split_once('#')
        .map_or(value, |(before_comment, _)| before_comment)
        .contains(';')
}

fn write_atomic_requirements(path: &Path, contents: &str) -> io::Result<()> {
    static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .map(|name| name.to_string_lossy())
        .unwrap_or_else(|| "requirements".into());
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();

    let mut temp = None;
    for _ in 0..100 {
        let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let candidate = parent.join(format!(
            ".{file_name}.blanket-edit-{stamp}-{}-{counter}",
            std::process::id()
        ));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(file) => {
                temp = Some((candidate, file));
                break;
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    let (temp, mut file) =
        temp.ok_or_else(|| other("could not create a unique requirements temp file"))?;
    #[cfg(unix)]
    if let Ok(metadata) = fs::metadata(path) {
        use std::os::unix::fs::PermissionsExt;
        if let Err(error) = fs::set_permissions(
            &temp,
            fs::Permissions::from_mode(metadata.permissions().mode()),
        ) {
            drop(file);
            let _ = fs::remove_file(&temp);
            return Err(error);
        }
    }
    if let Err(error) = file.write_all(contents.as_bytes()) {
        drop(file);
        let _ = fs::remove_file(&temp);
        return Err(error);
    }
    if let Err(error) = file.sync_all() {
        drop(file);
        let _ = fs::remove_file(&temp);
        return Err(error);
    }
    drop(file);
    if let Err(error) = fs::rename(&temp, path) {
        let _ = fs::remove_file(&temp);
        return Err(error);
    }
    Ok(())
}

fn uv_command(
    store: &Store,
    platform: Platform,
    project: &Path,
) -> io::Result<(Command, &'static str)> {
    let uv = python::ensure_uv_for(store, platform)?.join("uv");
    let selection =
        pyselect::select_python_with_inputs(platform, &manifest::python_inputs(project)?)?;
    let interpreter = python::ensure_python_for(store, selection.pin, platform)?;
    let mut command = Command::new(uv);
    command
        .current_dir(project)
        .env("UV_PYTHON", interpreter.join("bin/python3"))
        .env("UV_PYTHON_DOWNLOADS", "never")
        .env_remove("UV_INDEX_URL")
        .env_remove("UV_DEFAULT_INDEX")
        .env_remove("UV_EXTRA_INDEX_URL")
        .env_remove("PIP_INDEX_URL")
        .env_remove("PIP_EXTRA_INDEX_URL")
        .env_remove("PIP_TRUSTED_HOST")
        .env_remove("PIP_FIND_LINKS");
    Ok((command, selection.pin.version))
}

fn run_inherited(mut command: Command, what: &str) -> io::Result<()> {
    ui::trace_command(&command);
    let status = command
        .status()
        .map_err(|error| io::Error::new(error.kind(), format!("run {what}: {error}")))?;
    if !status.success() {
        return Err(other(format!(
            "{what} failed (exit status {status}); nothing was synced"
        )));
    }
    Ok(())
}

fn uv_compile(
    store: &Store,
    platform: Platform,
    project: &Path,
    input: &Path,
    output: &Path,
    extra: &[String],
) -> io::Result<()> {
    let (mut command, version) = uv_command(store, platform, project)?;
    command
        .args(["pip", "compile"])
        .arg(input)
        .arg("--generate-hashes");
    if !ui::verbose() {
        command.arg("--quiet");
    }
    command
        .args(["--python-version", version])
        .args(["--index-url", "https://pypi.org/simple"])
        .arg("-o")
        .arg(output)
        .args(extra);
    run_inherited(command, "store uv pip compile")
}

fn python_uv(
    store: &Store,
    platform: Platform,
    project: &Path,
    verb: Verb,
    texts: &[String],
    dev: bool,
) -> io::Result<Vec<String>> {
    validate_delegate_specs(texts)?;
    let (mut command, _) = uv_command(store, platform, project)?;
    match verb {
        Verb::Add => {
            command.args(["add", "--no-sync"]);
            if dev {
                command.arg("--dev");
            }
            if !texts.is_empty() {
                command.arg("--").args(texts);
            }
        }
        Verb::Remove => {
            command.args(["remove", "--no-sync"]);
            if dev {
                command.arg("--dev");
            }
            if !texts.is_empty() {
                command.arg("--").args(texts);
            }
        }
        Verb::Update => {
            command.arg("lock");
            if texts.is_empty() {
                command.arg("--upgrade");
            }
            for name in texts {
                command.args(["--upgrade-package", name]);
            }
        }
    }
    run_inherited(command, "store uv")?;
    Ok(vec!["pyproject.toml".to_string(), "uv.lock".to_string()])
}

// ---------------------------------------------------------------------------
// Node

#[derive(Debug, Clone, PartialEq, Eq)]
enum NodePackageManager {
    Pnpm {
        version: String,
        corepack_sha224: Option<String>,
    },
}

impl NodePackageManager {
    fn name(&self) -> &'static str {
        "pnpm"
    }

    fn version(&self) -> &str {
        let Self::Pnpm { version, .. } = self;
        version
    }

    fn corepack_sha224(&self) -> Option<&str> {
        let Self::Pnpm {
            corepack_sha224, ..
        } = self;
        corepack_sha224.as_deref()
    }

    fn executable(&self) -> &'static str {
        "pnpm"
    }
}

fn package_manager_version(
    value: &str,
    package_json: &Path,
) -> io::Result<(String, Option<String>)> {
    let (version, hash) = match value.split_once("+sha224.") {
        Some((version, hash)) => (version, Some(hash)),
        None => (value, None),
    };
    if let Some(hash) = hash {
        if hash.len() != 56 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(other(format!(
                "{}: packageManager has a malformed sha224 hash",
                package_json.display()
            )));
        }
    }
    if !xrun::is_exact_version(version) {
        return Err(other(format!(
            "{}: packageManager version must be an exact release such as pnpm@9.12.3 (a prerelease suffix is allowed)",
            package_json.display()
        )));
    }
    Ok((version.to_string(), hash.map(str::to_ascii_lowercase)))
}

fn parse_package_manager_value(value: &str, package_json: &Path) -> io::Result<NodePackageManager> {
    let version = value.strip_prefix("pnpm@").ok_or_else(|| {
        other(format!(
            "{}: packageManager must be pnpm@<exact-version>, found {value:?}",
            package_json.display()
        ))
    })?;
    let (version, corepack_sha224) = package_manager_version(version, package_json)?;
    Ok(NodePackageManager::Pnpm {
        version,
        corepack_sha224,
    })
}

fn pnpm_lock_major(lock_text: &str) -> Option<String> {
    let version = lock_text.lines().find_map(|line| {
        line.trim()
            .strip_prefix("lockfileVersion:")
            .map(|version| version.trim().trim_matches(['\'', '"']))
    })?;
    let major = version.split('.').next()?.trim();
    (!major.is_empty() && major.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| major.to_string())
}

fn node_package_manager(root: &Path, lock_text: &str) -> io::Result<NodePackageManager> {
    let package_json = root.join("package.json");
    let text = fs::read_to_string(&package_json).map_err(|error| {
        other(format!(
            "read {}: {error}; add a package.json with a packageManager field",
            package_json.display()
        ))
    })?;
    let value: serde_json::Value = serde_json::from_str(&text)
        .map_err(|error| other(format!("{}: {error}", package_json.display())))?;
    let field = value.get("packageManager").ok_or_else(|| {
        let major = pnpm_lock_major(lock_text)
            .map(|major| format!(" this lock was written by pnpm major {major};"))
            .unwrap_or_default();
        other(format!(
            "{}: packageManager is required;{major} add \"packageManager\": \"pnpm@<major.minor.patch>\" using the exact version the team runs (pnpm --version)",
            package_json.display()
        ))
    })?;
    let value = field.as_str().ok_or_else(|| {
        other(format!(
            "{}: packageManager must be a string like pnpm@9.12.3",
            package_json.display()
        ))
    })?;
    parse_package_manager_value(value, &package_json)
}

fn node_lock_at(directory: &Path) -> Option<&'static str> {
    ["package-lock.json", "pnpm-lock.yaml", "yarn.lock"]
        .into_iter()
        .find(|name| directory.join(name).is_file())
}

fn workspace_segment_matches(pattern: &str, value: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let value: Vec<char> = value.chars().collect();
    let mut row = vec![false; value.len() + 1];
    row[0] = true;
    for character in pattern {
        let mut next = vec![false; value.len() + 1];
        for (index, matched) in row.iter().enumerate() {
            if !matched {
                continue;
            }
            if character == '*' {
                for slot in &mut next[index..] {
                    *slot = true;
                }
            } else if index < value.len() && value[index] == character {
                next[index + 1] = true;
            }
        }
        row = next;
    }
    row[value.len()]
}

fn workspace_glob_matches(pattern: &str, path: &str) -> bool {
    let pattern: Vec<&str> = pattern.split('/').filter(|part| !part.is_empty()).collect();
    let path: Vec<&str> = path.split('/').filter(|part| !part.is_empty()).collect();
    fn matches(pattern: &[&str], path: &[&str]) -> bool {
        if pattern.is_empty() {
            return path.is_empty();
        }
        if pattern[0] == "**" {
            matches(&pattern[1..], path) || (!path.is_empty() && matches(pattern, &path[1..]))
        } else {
            !path.is_empty()
                && workspace_segment_matches(pattern[0], path[0])
                && matches(&pattern[1..], &path[1..])
        }
    }
    matches(&pattern, &path)
}

fn pnpm_workspace_contains(root: &Path, project: &Path) -> io::Result<(bool, Vec<String>)> {
    let workspace_file = root.join("pnpm-workspace.yaml");
    let patterns = if workspace_file.is_file() {
        let text = fs::read_to_string(&workspace_file)
            .map_err(|error| other(format!("read {}: {error}", workspace_file.display())))?;
        crate::npm_lock_import::pnpm_workspace_packages(&text)
            .map_err(|error| other(format!("{}: {error}", workspace_file.display())))?
    } else {
        Vec::new()
    };
    let root = root.canonicalize()?;
    let project = project.canonicalize()?;
    let relative = project.strip_prefix(&root).map_err(|_| {
        other(format!(
            "project {} is outside pnpm workspace root {}",
            project.display(),
            root.display()
        ))
    })?;
    let relative = relative.to_string_lossy().replace('\\', "/");
    let mut matched = false;
    for raw_pattern in &patterns {
        let trimmed = raw_pattern.trim();
        let exclude = trimmed.starts_with('!');
        let pattern = trimmed
            .strip_prefix('!')
            .unwrap_or(trimmed)
            .trim()
            .trim_start_matches("./");
        if pattern.is_empty()
            || pattern.starts_with('/')
            || pattern.contains('\\')
            || pattern.split('/').any(|part| part == "..")
        {
            return Err(other(format!(
                "{}: unsafe pnpm workspace glob {raw_pattern:?}",
                root.join("pnpm-workspace.yaml").display()
            )));
        }
        if workspace_glob_matches(pattern, &relative) {
            matched = !exclude;
        }
    }
    Ok((matched, patterns))
}

/// Select the lockfile to edit. A lockfile in the project itself wins in the
/// same order as sync. Only a pnpm workspace root may be inherited, and only
/// when its declared package globs contain the project.
fn node_lock_selection(project: &Path) -> io::Result<(String, PathBuf)> {
    if let Some(lock_name) = node_lock_at(project) {
        return Ok((lock_name.to_string(), project.to_path_buf()));
    }
    if project.join(".blanket").is_dir() {
        return Ok(("package-lock.json".to_string(), project.to_path_buf()));
    }
    for ancestor in project.ancestors().skip(1) {
        if let Some(lock_name) = node_lock_at(ancestor) {
            if lock_name == "pnpm-lock.yaml" {
                let (matched, patterns) = pnpm_workspace_contains(ancestor, project)?;
                if !matched {
                    return Err(other(format!(
                        "project {} is not included by pnpm workspace root {}; packages globs: {}",
                        project.display(),
                        ancestor.display(),
                        if patterns.is_empty() {
                            "<none>".to_string()
                        } else {
                            patterns.join(", ")
                        }
                    )));
                }
            }
            return Ok((lock_name.to_string(), ancestor.to_path_buf()));
        }
        if ancestor.join(".blanket").is_dir() {
            break;
        }
    }
    Ok(("package-lock.json".to_string(), project.to_path_buf()))
}

fn node_delegate_args(
    verb: Verb,
    texts: &[String],
    dev: bool,
    workspace_root: bool,
) -> Vec<String> {
    let command = match verb {
        Verb::Add => "add",
        Verb::Remove => "remove",
        Verb::Update => "update",
    };
    let mut args = vec![command.to_string()];
    args.extend(["--lockfile-only", "--reporter", "append-only"].map(str::to_string));
    if workspace_root {
        args.push("-w".into());
    }
    if dev && verb == Verb::Add {
        args.push("-D".into());
    }
    if !texts.is_empty() {
        args.push("--".into());
        args.extend(texts.iter().cloned());
    }
    args
}

/// Keep pnpm's isolated data directory stable for one project. pnpm embeds
/// its store location in node_modules, so a fresh stage for every edit would
/// make the next edit reject the existing installation as belonging to a
/// different store. This is scratch state, not a published blanket object.
fn pnpm_home(store: &Store, project: &Path) -> io::Result<PathBuf> {
    let project = project.canonicalize()?;
    let key = hex::encode(Sha256::digest(
        format!("pnpm-edit\0{}\0{}", store.root.display(), project.display()).as_bytes(),
    ));
    let home = store
        .root
        .join("tmp")
        .join(format!("pnpm-home-{}", &key[..32]));
    fs::create_dir_all(&home)?;
    Ok(home)
}

struct NodeEdit {
    files: Vec<String>,
    sync_project: PathBuf,
}

fn node(
    store: &Store,
    platform: Platform,
    project: &Path,
    verb: Verb,
    texts: &[String],
    dev: bool,
) -> io::Result<NodeEdit> {
    validate_delegate_specs(texts)?;
    let (lock_name, lock_root) = node_lock_selection(project)?;
    if lock_name == "package-lock.json" {
        let node_obj = npm::ensure_node_for(store, platform)?;
        let mut command = Command::new(node_obj.join("bin/npm"));
        if !ui::verbose() {
            command.arg("--silent");
        }
        match verb {
            Verb::Add => {
                command.args(["install", "--package-lock-only", "--ignore-scripts"]);
                if dev {
                    command.arg("--save-dev");
                }
                if !texts.is_empty() {
                    command.arg("--").args(texts);
                }
            }
            Verb::Remove => {
                command.args(["uninstall", "--package-lock-only", "--ignore-scripts"]);
                if !texts.is_empty() {
                    command.arg("--").args(texts);
                }
            }
            Verb::Update => {
                command.args(["update", "--package-lock-only", "--ignore-scripts"]);
                if !texts.is_empty() {
                    command.arg("--").args(texts);
                }
            }
        }
        command.current_dir(project).env(
            "PATH",
            format!(
                "{}:{}",
                node_obj.join("bin").display(),
                std::env::var("PATH").unwrap_or_default()
            ),
        );
        run_inherited(command, "store npm")?;
        return Ok(NodeEdit {
            files: vec!["package.json".into(), "package-lock.json".into()],
            sync_project: project.to_path_buf(),
        });
    }
    let lock_text = fs::read_to_string(lock_root.join(&lock_name))?;
    if lock_name == "yarn.lock" {
        let tool_verb = match verb {
            Verb::Add => "add",
            Verb::Remove => "remove",
            Verb::Update => "update",
        };
        return Err(other(format!(
            "this project is locked by yarn (yarn.lock) and yarn is not a pinned tool; run 'yarn {tool_verb}{}{}', then 'blanket' (it imports yarn.lock)",
            if dev && verb == Verb::Add { " -D" } else { "" },
            texts.iter().map(|text| format!(" {text}")).collect::<String>()
        )));
    }
    let manager = node_package_manager(&lock_root, &lock_text)?;
    let tool_root = xrun::realize_node_tool(
        store,
        platform,
        manager.name(),
        manager.version(),
        manager.corepack_sha224(),
    )?;
    let node_obj = npm::ensure_node_for(store, platform)?;
    let executable = tool_root
        .join("node_modules/.bin")
        .join(manager.executable());
    if !executable.is_file() {
        return Err(other(format!(
            "store {}@{} has no {} executable",
            manager.name(),
            manager.version(),
            manager.name()
        )));
    }
    let args = node_delegate_args(
        verb,
        texts,
        dev,
        lock_name == "pnpm-lock.yaml"
            && project == lock_root
            && lock_root.join("pnpm-workspace.yaml").is_file(),
    );
    let package_path = project.join("package.json");
    let pnpm_home_dir = pnpm_home(store, project)?;
    let pnpm_config = pnpm_home_dir.join("xdg-config");
    let pnpm_data = pnpm_home_dir.join("xdg-data");
    let pnpm_cache = pnpm_home_dir.join("xdg-cache");
    let pnpm_state = pnpm_home_dir.join("xdg-state");
    let result = (|| -> io::Result<()> {
        let mut command = Command::new(&executable);
        command.args(&args).current_dir(project).env(
            "PATH",
            format!(
                "{}:{}:{}",
                node_obj.join("bin").display(),
                tool_root.join("node_modules/.bin").display(),
                std::env::var("PATH").unwrap_or_default()
            ),
        );
        command
            .env("HOME", &pnpm_home_dir)
            .env("XDG_CONFIG_HOME", &pnpm_config)
            .env("XDG_DATA_HOME", &pnpm_data)
            .env("XDG_CACHE_HOME", &pnpm_cache)
            .env("XDG_STATE_HOME", &pnpm_state);
        sandbox::force_env(
            &mut command,
            &["npm_config_", "NPM_CONFIG_", "PNPM_", "YARN_", "COREPACK_"],
            &["NODE_OPTIONS"],
            &[("CI".into(), "1".into())],
        );
        run_inherited(command, &format!("store {}", manager.name()))?;
        Ok(())
    })();
    result?;
    let package_label = package_path
        .strip_prefix(&lock_root)
        .unwrap_or(&package_path)
        .to_string_lossy()
        .into_owned();
    Ok(NodeEdit {
        files: vec![package_label, lock_name.to_string()],
        sync_project: lock_root,
    })
}

// ---------------------------------------------------------------------------
// Cargo

fn cargo_delegate(
    store: &Store,
    platform: Platform,
    project: &Path,
    verb: Verb,
    texts: &[String],
    dev: bool,
) -> io::Result<Vec<String>> {
    validate_delegate_specs(texts)?;
    let version = cargo::resolve_toolchain(platform, project)?;
    let rust_obj = cargo::ensure_rust_for(store, platform, version)?;
    let mut command = Command::new(rust_obj.join("bin/cargo"));
    match verb {
        Verb::Add => {
            command.arg("add");
            if dev {
                command.arg("--dev");
            }
            if !texts.is_empty() {
                command.arg("--").args(texts);
            }
        }
        Verb::Remove => {
            command.arg("remove");
            if dev {
                command.arg("--dev");
            }
            if !texts.is_empty() {
                command.arg("--").args(texts);
            }
        }
        Verb::Update => {
            command.arg("update");
            for name in texts {
                command.args(["-p", name]);
            }
        }
    }
    command
        .current_dir(project)
        .env("CARGO_NET_OFFLINE", "false")
        .env_remove("RUSTUP_HOME")
        .env_remove("RUSTUP_TOOLCHAIN");
    run_inherited(command, "store cargo")?;
    Ok(vec!["Cargo.toml".to_string(), "Cargo.lock".to_string()])
}

// ---------------------------------------------------------------------------
// Go

fn go_delegate(
    store: &Store,
    platform: Platform,
    project: &Path,
    verb: Verb,
    texts: &[String],
    dev: bool,
) -> io::Result<Vec<String>> {
    validate_delegate_specs(texts)?;
    if dev {
        return Err(other(
            "--dev has no meaning in Go (one dependency set per module)",
        ));
    }
    let go_obj = golang::ensure_go_for(store, platform)?;
    let scratch = store.stage()?;
    let args: Vec<String> = match verb {
        Verb::Add => std::iter::once("get".to_string())
            .chain(texts.iter().cloned())
            .collect(),
        Verb::Remove => std::iter::once("get".to_string())
            .chain(texts.iter().map(|name| format!("{name}@none")))
            .collect(),
        Verb::Update => {
            let mut args = vec!["get".to_string(), "-u".to_string()];
            if texts.is_empty() {
                args.push("./...".to_string());
            }
            args.extend(texts.iter().cloned());
            args
        }
    };
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let result = golang::run_checked(&go_obj, project, &scratch, false, &refs);
    let _ = crate::store::remove_tree(&scratch);
    result?;
    Ok(vec!["go.mod".to_string(), "go.sum".to_string()])
}

// ---------------------------------------------------------------------------
// Ruby

fn ruby_delegate(
    store: &Store,
    platform: Platform,
    project: &Path,
    verb: Verb,
    texts: &[String],
    dev: bool,
) -> io::Result<Vec<String>> {
    validate_delegate_specs(texts)?;
    let ruby_obj = ruby::ensure_ruby_for(store, platform)?;
    let scratch = store.stage()?;
    let result = (|| -> io::Result<()> {
        match verb {
            Verb::Add => {
                for text in texts {
                    let (name, constraint) = text.split_once('@').unwrap_or((text, ""));
                    let mut args = vec!["bundle", "add", name];
                    if !constraint.is_empty() {
                        args.extend(["--version", constraint]);
                    }
                    if dev {
                        args.extend(["--group", "development"]);
                    }
                    ruby::run_checked(&ruby_obj, project, &scratch, &args)?;
                }
                Ok(())
            }
            Verb::Remove => {
                let mut args = vec!["bundle", "remove"];
                args.extend(texts.iter().map(String::as_str));
                ruby::run_checked(&ruby_obj, project, &scratch, &args)
            }
            Verb::Update => {
                let mut args = vec!["bundle", "update"];
                if texts.is_empty() {
                    args.push("--all");
                }
                args.extend(texts.iter().map(String::as_str));
                ruby::run_checked(&ruby_obj, project, &scratch, &args)
            }
        }
    })();
    let _ = crate::store::remove_tree(&scratch);
    result?;
    Ok(vec!["Gemfile".to_string(), "Gemfile.lock".to_string()])
}

// ---------------------------------------------------------------------------
// Elixir

fn elixir_delegate(
    store: &Store,
    platform: Platform,
    project: &Path,
    verb: Verb,
    texts: &[String],
) -> io::Result<Vec<String>> {
    validate_delegate_specs(texts)?;
    match verb {
        Verb::Add => {
            let lines = texts
                .iter()
                .map(|text| {
                    let (name, constraint) = text.split_once('@').unwrap_or((text, "~> x.y"));
                    format!("{{:{name}, \"{constraint}\"}}")
                })
                .collect::<Vec<_>>()
                .join(", ");
            Err(other(format!(
                "there is no 'mix add': put {lines} in the deps list of mix.exs, then 'blanket' (it runs mix deps.get and re-locks)"
            )))
        }
        Verb::Remove => Err(other(format!(
            "there is no 'mix remove': delete {} from the deps list of mix.exs, then 'blanket'",
            texts
                .iter()
                .map(|name| format!("{{:{name}, ...}}"))
                .collect::<Vec<_>>()
                .join(", ")
        ))),
        Verb::Update => {
            let beam = elixir::ensure_beam_for(store, platform)?;
            let scratch = store.stage()?;
            let mut args = vec!["mix", "deps.update"];
            if texts.is_empty() {
                args.push("--all");
            }
            args.extend(texts.iter().map(String::as_str));
            let result = elixir::run_checked(&beam, project, &scratch, false, &args);
            let _ = crate::store::remove_tree(&scratch);
            result?;
            Ok(vec!["mix.lock".to_string()])
        }
    }
}

// ---------------------------------------------------------------------------
// .NET

fn dotnet_refuse(verb: Verb, texts: &[String]) -> io::Result<Vec<String>> {
    validate_delegate_specs(texts)?;
    let names = texts.join(" ");
    Err(other(match verb {
        Verb::Add => format!(
            "blanket never evaluates MSBuild outside the sandbox, and 'dotnet add package' restores: run 'dotnet add package {names}' then 'dotnet restore --force-evaluate' with your own SDK, commit packages.lock.json, then 'blanket'"
        ),
        Verb::Remove => format!(
            "run 'dotnet remove package {names}' then 'dotnet restore --force-evaluate' with your own SDK, commit packages.lock.json, then 'blanket'"
        ),
        Verb::Update => "edit the PackageReference versions, run 'dotnet restore --force-evaluate' with your own SDK, commit packages.lock.json, then 'blanket'".to_string(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(text: &str) -> Spec {
        parse_spec(text)
    }

    #[test]
    fn specs_split_prefix_name_and_constraint() {
        assert_eq!(
            spec("npm:react@18"),
            Spec {
                text: "react@18".into(),
                name: "react".into(),
                eco: Some(Eco::Node)
            }
        );
        assert_eq!(spec("py:requests>=2,<3").name, "requests");
        assert_eq!(spec("py:requests>=2,<3").text, "requests>=2,<3");
        assert_eq!(spec("@types/node@20").name, "@types/node");
        assert_eq!(spec("@types/node@20").eco, None);
        assert_eq!(spec("gem:rails@~> 7.1").name, "rails");
        assert_eq!(spec("go:github.com/x/y@v1.2.3").name, "github.com/x/y");
        assert_eq!(spec("requests[socks]").name, "requests");
        assert_eq!(spec("unknown:thing").name, "unknown:thing");
        assert_eq!(spec("unknown:thing").eco, None);
        assert_eq!(spec("nuget:Newtonsoft.Json").eco, Some(Eco::Dotnet));
    }

    #[test]
    fn specs_reject_empty_options_and_control_bytes() {
        for text in [
            "",
            "   ",
            "--prefix=/tmp/elsewhere",
            "npm:--prefix=/tmp/elsewhere",
            "cargo:--manifest-path=/tmp/Cargo.toml",
            "npm:\nreact",
            "requests\0evil",
        ] {
            assert!(
                validate_spec(text).is_err(),
                "accepted unsafe spec {text:?}"
            );
        }
        assert!(validate_spec("npm:react@18").is_ok());
        assert!(validate_spec("gem:rails@~> 7.1").is_ok());
    }

    #[test]
    fn pnpm_package_manager_requires_an_exact_release_and_verifies_hash_syntax() {
        let package_json = Path::new("package.json");
        for (value, accepted) in [
            ("pnpm@9", false),
            ("pnpm@9.x", false),
            ("pnpm@^9.1.0", false),
            ("pnpm@latest", false),
            ("pnpm@9.01.2", false),
            ("pnpm@9.1.2", true),
        ] {
            assert_eq!(
                parse_package_manager_value(value, package_json).is_ok(),
                accepted,
                "unexpected acceptance for {value}"
            );
        }
        assert_eq!(
            parse_package_manager_value("pnpm@9.12.3", package_json).unwrap(),
            NodePackageManager::Pnpm {
                version: "9.12.3".into(),
                corepack_sha224: None,
            }
        );
        assert_eq!(
            parse_package_manager_value(
                &format!("pnpm@9.1.2-rc.1+sha224.{}", "A".repeat(56)),
                package_json
            )
            .unwrap(),
            NodePackageManager::Pnpm {
                version: "9.1.2-rc.1".into(),
                corepack_sha224: Some("a".repeat(56)),
            }
        );
        let garbage =
            parse_package_manager_value("not-a-package-manager", package_json).unwrap_err();
        assert!(garbage.to_string().contains("packageManager"), "{garbage}");
        let malformed_hash =
            parse_package_manager_value("pnpm@9.1.2+sha224.not-a-hash", package_json).unwrap_err();
        assert!(malformed_hash.to_string().contains("malformed sha224"));
    }

    #[test]
    fn missing_pnpm_package_manager_names_lock_major_without_floating_suggestion() {
        let root = std::env::temp_dir().join(format!(
            "blanket-node-package-manager-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("package.json"), "{}\n").unwrap();
        let missing = node_package_manager(&root, "lockfileVersion: '9.0'\n").unwrap_err();
        let missing = missing.to_string();
        assert!(
            missing.contains("lock was written by pnpm major 9"),
            "{missing}"
        );
        assert!(missing.contains(
            "add \"packageManager\": \"pnpm@<major.minor.patch>\" using the exact version the team runs (pnpm --version)"
        ));
        assert!(!missing.contains("pnpm@9\""), "{missing}");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn node_delegate_argv_is_delimited_and_workspace_aware() {
        let args = node_delegate_args(Verb::Add, &["@scope/pkg@1.2.3".into()], true, true);
        assert_eq!(
            args,
            vec![
                "add",
                "--lockfile-only",
                "--reporter",
                "append-only",
                "-w",
                "-D",
                "--",
                "@scope/pkg@1.2.3"
            ]
        );
        assert!(validate_delegate_specs(&["--prefix=/tmp".into()]).is_err());
    }

    #[test]
    fn node_lock_selection_prefers_own_lock_and_checks_pnpm_workspace_globs() {
        let root = std::env::temp_dir().join(format!(
            "blanket-node-lock-selection-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("packages/lib")).unwrap();
        fs::create_dir_all(root.join("packages/private")).unwrap();
        fs::write(root.join("pnpm-lock.yaml"), "lockfileVersion: '9.0'\n").unwrap();
        fs::write(
            root.join("pnpm-workspace.yaml"),
            "packages:\n  - packages/*\n  - '!packages/private'\n",
        )
        .unwrap();
        let member = root.join("packages/lib");
        assert_eq!(
            node_lock_selection(&member).unwrap(),
            ("pnpm-lock.yaml".to_string(), root.clone())
        );
        assert!(workspace_glob_matches("packages/*", "packages/lib"));
        assert!(workspace_glob_matches(
            "packages/**",
            "packages/private/deep"
        ));
        assert!(!workspace_glob_matches(
            "packages/*",
            "packages/private/deep"
        ));

        let independent = root.join("packages/private");
        let error = node_lock_selection(&independent).unwrap_err();
        assert!(
            error.to_string().contains(&root.display().to_string()),
            "{error}"
        );
        assert!(error.to_string().contains("packages/*"), "{error}");

        fs::write(independent.join("package-lock.json"), "{}\n").unwrap();
        assert_eq!(
            node_lock_selection(&independent).unwrap(),
            ("package-lock.json".to_string(), independent.clone())
        );

        fs::write(member.join("package-lock.json"), "{}\n").unwrap();
        fs::write(root.join("package-lock.json"), "{}\n").unwrap();
        assert_eq!(
            node_lock_selection(&member).unwrap(),
            ("package-lock.json".to_string(), member)
        );

        let boundary = root.join("packages/boundary");
        fs::create_dir_all(boundary.join(".blanket")).unwrap();
        assert_eq!(
            node_lock_selection(&boundary).unwrap(),
            ("package-lock.json".to_string(), boundary)
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn shapes_are_structural() {
        assert_eq!(shape("@types/node"), Some(Eco::Node));
        assert_eq!(shape("github.com/spf13/cobra"), Some(Eco::Go));
        assert_eq!(shape("Newtonsoft.Json"), Some(Eco::Dotnet));
        assert_eq!(shape("Microsoft.Extensions.Logging"), Some(Eco::Dotnet));
        assert_eq!(shape("requests"), None);
        assert_eq!(shape("react"), None);
        assert_eq!(shape("ruff"), None);
        assert_eq!(shape("zope.interface"), None); // lowercase dotted: PyPI
        assert_eq!(shape("./local/path"), None);
    }

    #[test]
    fn ladder_stops_at_the_first_answer() {
        use std::cell::RefCell;
        let lookups: RefCell<Vec<(Eco, String)>> = RefCell::new(Vec::new());
        let asked: RefCell<Vec<(String, Vec<(Eco, String)>)>> = RefCell::new(Vec::new());
        let mut lookup = |eco: Eco, name: &str| -> io::Result<Option<String>> {
            lookups.borrow_mut().push((eco, name.to_string()));
            Ok(match (eco, name) {
                (Eco::Python, "requests") => Some("2.32.5".into()),
                (Eco::Node, "requests") => Some("0.3.0".into()),
                (Eco::Node, "react") => Some("19.0.0".into()),
                _ => None,
            })
        };
        let mut ask = |name: &str, known: &[(Eco, String)]| -> io::Result<Eco> {
            asked.borrow_mut().push((name.to_string(), known.to_vec()));
            Ok(known[0].0)
        };
        let both = [Eco::Python, Eco::Node];

        // Rung 1: prefix, no lookup.
        assert_eq!(
            choose(&spec("npm:react"), &both, &mut lookup, &mut ask).unwrap(),
            Eco::Node
        );
        // Rung 2: shape, no lookup.
        assert_eq!(
            choose(&spec("@types/node"), &both, &mut lookup, &mut ask).unwrap(),
            Eco::Node
        );
        // Rung 2 against a project without that ecosystem is an error.
        let error = choose(&spec("github.com/x/y"), &both, &mut lookup, &mut ask).unwrap_err();
        assert!(error.to_string().contains("no go manifest"), "{error}");
        // Rung 3 skipped when one ecosystem is present, no lookup.
        assert_eq!(
            choose(&spec("react"), &[Eco::Node], &mut lookup, &mut ask).unwrap(),
            Eco::Node
        );
        assert!(lookups.borrow().is_empty());
        // Rung 3: registries decide when exactly one knows the name.
        assert_eq!(
            choose(&spec("react"), &both, &mut lookup, &mut ask).unwrap(),
            Eco::Node
        );
        assert_eq!(lookups.borrow().len(), 2);
        // Rung 3, nobody knows: error names the explicit spellings.
        let error = choose(&spec("nothing"), &both, &mut lookup, &mut ask).unwrap_err();
        assert!(
            error.to_string().contains("py:nothing / npm:nothing"),
            "{error}"
        );
        assert!(asked.borrow().is_empty());
        // Rung 4: both know it → ask, with the versions.
        assert_eq!(
            choose(&spec("requests"), &both, &mut lookup, &mut ask).unwrap(),
            Eco::Python
        );
        let asked = asked.borrow();
        assert_eq!(asked.len(), 1);
        assert_eq!(asked[0].1[0], (Eco::Python, "2.32.5".to_string()));
        assert_eq!(asked[0].1[1], (Eco::Node, "0.3.0".to_string()));
    }

    #[test]
    fn requirement_names_and_edits() {
        assert_eq!(
            requirement_name("Requests>=2 ; python_version<'3'"),
            Some("requests".into())
        );
        assert_eq!(
            requirement_name("zope.Interface[x]==5"),
            Some("zope-interface".into())
        );
        assert_eq!(requirement_name("# comment"), None);
        assert_eq!(requirement_name("-r other.txt"), None);
        assert_eq!(requirement_name("--hash=sha256:abc"), None);
        assert_eq!(requirement_name(""), None);

        let temp = std::env::temp_dir().join(format!("blanket-deps-{}", std::process::id()));
        fs::create_dir_all(&temp).unwrap();
        let file = temp.join("requirements.txt");
        fs::write(&file, "# pinned\nsix==1.16.0\n-r extra.txt\n").unwrap();
        edit_requirements(&file, &["requests>=2".into(), "six==1.17.0".into()], &[]).unwrap();
        assert_eq!(
            fs::read_to_string(&file).unwrap(),
            "# pinned\nsix==1.17.0\n-r extra.txt\nrequests>=2\n"
        );
        edit_requirements(&file, &[], &["SIX".into()]).unwrap();
        assert_eq!(
            fs::read_to_string(&file).unwrap(),
            "# pinned\n-r extra.txt\nrequests>=2\n"
        );
        let error = edit_requirements(&file, &[], &["six".into()]).unwrap_err();
        assert!(error.to_string().contains("'six' is not declared"));
        let error = edit_requirements(&file, &["-e .".into()], &[]).unwrap_err();
        assert!(error.to_string().contains("not a requirement"));
        let _ = fs::remove_dir_all(&temp);
    }

    #[test]
    fn requirement_edits_are_logical_lossless_and_ambiguous_edits_fail() {
        let temp =
            std::env::temp_dir().join(format!("blanket-deps-logical-{}", std::process::id()));
        let _ = fs::remove_dir_all(&temp);
        fs::create_dir_all(&temp).unwrap();
        let file = temp.join("requirements.txt");
        fs::write(
            &file,
            "# pinned\r\nfoo==1.0 \\\r\n    --hash=sha256:abc\r\nbar==2.0",
        )
        .unwrap();
        edit_requirements(&file, &[], &["foo".into()]).unwrap();
        assert_eq!(fs::read_to_string(&file).unwrap(), "# pinned\r\nbar==2.0");

        fs::write(
            &file,
            "foo==1; python_version<'3'\nfoo==2; python_version>='3'\n",
        )
        .unwrap();
        let error = edit_requirements(&file, &["foo==3".into()], &[]).unwrap_err();
        assert!(error.to_string().contains("ambiguous"), "{error}");
        assert_eq!(
            fs::read_to_string(&file).unwrap(),
            "foo==1; python_version<'3'\nfoo==2; python_version>='3'\n"
        );

        fs::write(&file, "foo==1; python_version<'3'\n").unwrap();
        let error = edit_requirements(&file, &["foo==3".into()], &[]).unwrap_err();
        assert!(error.to_string().contains("environment marker"), "{error}");
        edit_requirements(&file, &["foo==3; python_version<'3'".into()], &[]).unwrap();
        assert_eq!(
            fs::read_to_string(&file).unwrap(),
            "foo==3; python_version<'3'\n"
        );

        let error = edit_requirements(&file, &["foo\nbar".into()], &[]).unwrap_err();
        assert!(error.to_string().contains("CR, LF, or NUL"), "{error}");
        let _ = fs::remove_dir_all(&temp);
    }

    #[cfg(unix)]
    #[test]
    fn requirement_edit_does_not_follow_predictable_temp_symlink() {
        use std::os::unix::fs::symlink;
        use std::os::unix::fs::PermissionsExt;

        let temp = std::env::temp_dir().join(format!("blanket-deps-atomic-{}", std::process::id()));
        let _ = fs::remove_dir_all(&temp);
        fs::create_dir_all(&temp).unwrap();
        let file = temp.join("requirements.txt");
        let target = temp.join("outside");
        let old_temp = file.with_extension(format!("blanket-edit.{}", std::process::id()));
        fs::write(&file, "six\n").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&target, "must remain\n").unwrap();
        symlink(&target, &old_temp).unwrap();

        edit_requirements(&file, &["requests".into()], &[]).unwrap();
        assert_eq!(fs::read_to_string(&target).unwrap(), "must remain\n");
        assert_eq!(fs::read_to_string(&file).unwrap(), "six\nrequests\n");
        assert_eq!(
            fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let _ = fs::remove_dir_all(&temp);
    }

    #[test]
    fn python_shapes_follow_the_sync_order() {
        let temp = std::env::temp_dir().join(format!("blanket-shape-{}", std::process::id()));
        let _ = fs::remove_dir_all(&temp);
        fs::create_dir_all(&temp).unwrap();
        assert!(python_shape(&temp).is_err());
        fs::write(temp.join("setup.py"), "").unwrap();
        assert_eq!(python_shape(&temp).unwrap(), PyShape::Setup);
        fs::write(temp.join("pyproject.toml"), "[project]\nname='x'\n").unwrap();
        assert_eq!(python_shape(&temp).unwrap(), PyShape::Uv);
        fs::write(temp.join("pyproject.toml"), "[tool.poetry]\nname='x'\n").unwrap();
        assert_eq!(python_shape(&temp).unwrap(), PyShape::Poetry);
        fs::write(temp.join("pyproject.toml"), "[project]\nname='x'\n").unwrap();
        fs::write(temp.join("pdm.lock"), "").unwrap();
        assert_eq!(python_shape(&temp).unwrap(), PyShape::Pdm);
        // requirements.txt wins over pyproject, as in sync.
        fs::write(temp.join("requirements.txt"), "six\n").unwrap();
        assert_eq!(
            python_shape(&temp).unwrap(),
            PyShape::Requirements(temp.join("requirements.txt"))
        );
        fs::write(temp.join("requirements.in"), "six\n").unwrap();
        assert_eq!(python_shape(&temp).unwrap(), PyShape::PipCompile);
        let _ = fs::remove_dir_all(&temp);
    }

    #[test]
    fn upgrade_flags_shape() {
        assert!(upgrade_flags(Verb::Add, &["x".into()]).is_empty());
        assert_eq!(upgrade_flags(Verb::Update, &[]), vec!["--upgrade"]);
        assert_eq!(
            upgrade_flags(Verb::Update, &["a".into(), "b".into()]),
            vec!["--upgrade-package", "a", "--upgrade-package", "b"]
        );
    }
}

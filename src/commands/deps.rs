//! `add`, `remove`, `update`.
//!
//! Doctrine: resolution belongs to the ecosystem's pinned tool, realization
//! belongs to tog. Every manifest or lock edit below is delegated to a
//! store tool (uv, the store node's npm, pinned pnpm, cargo, go, bundler, mix)
//! running unsandboxed with network — the same trust boundary as
//! missing-lockfile generation. Where no pinned tool can make the edit,
//! tog **refuses with the exact line and file**; that is still one tool
//! telling the user what to type next. Tog edits a file itself in exactly
//! one case: a plain requirements file, where the "tool" is a text append.
//!
//! Choosing the ecosystem is an evidence ladder: an explicit prefix, the
//! name's shape, the nearest manifest, the registries, then the human.
//! Never a coin flip.

use std::fs;
use std::fs::OpenOptions;
use std::io::{self, BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::commands::inspect;
use crate::commands::shared::{project_dir, selected_toolchain};
use crate::commands::sync;
use crate::commands::x as xrun;
use crate::kernel::activity::StoreActivity;
use crate::kernel::context::Context;
use crate::kernel::fsroot::ProjectRoot;
use crate::kernel::platform::Platform;
use crate::kernel::policy;
use crate::kernel::sandbox;
use crate::kernel::store::Store;
use crate::kernel::ui;
use crate::tailors::cargo;
use crate::tailors::elixir;
use crate::tailors::go;
use crate::tailors::node;
use crate::tailors::python;
use crate::tailors::python::pypi;
use crate::tailors::ruby;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verb {
    Add,
    Remove,
    Update,
}

impl Verb {
    fn command(self) -> &'static str {
        match self {
            Verb::Add => "add",
            Verb::Remove => "remove",
            Verb::Update => "update",
        }
    }

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
        .user_agent("tog (https://github.com/DigitalWestern/tog)")
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

/// Rung 4: does the registry know this name? `Some(latest version)`.
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

/// Rung 5: the human, or an error when there is no terminal.
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
        "tog: '{name}' exists on {}. Which one?",
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
        write!(stderr, "tog: [1-{}] ", known.len())?;
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
pub fn edit(
    platform: Platform,
    activity: &StoreActivity,
    cwd: &Path,
    request: Request,
    attribution: &mut policy::Attribution,
) -> io::Result<Outcome> {
    // Validate every spec before discovering the project, opening the store,
    // looking anything up in a registry, or invoking a package manager.
    for text in &request.specs {
        validate_spec(text)?;
    }
    let (project, present) = nearest_project(cwd)?;
    if project != cwd {
        ui::note(&format!("project: {}", project.display()));
    }
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
    reject_mixed_sync_roots(request.verb, &project, &groups)?;
    let store = Store::open()?;
    // Every delegated tool below runs under the command's own lease.
    store.require_activity(activity, "dependency edit")?;
    let mut lines = Vec::new();
    let mut outcome_project = project.clone();
    for (eco, specs) in groups {
        let names: Vec<String> = specs.iter().map(|spec| spec.name.clone()).collect();
        let texts: Vec<String> = specs.iter().map(|spec| spec.text.clone()).collect();
        let files = match eco {
            Eco::Python => python(
                &store,
                activity,
                platform,
                &project,
                request.verb,
                &texts,
                &names,
                request.dev,
                attribution,
            )?,
            Eco::Node => {
                let outcome = node(
                    &store,
                    activity,
                    platform,
                    &project,
                    request.verb,
                    &texts,
                    request.dev,
                    attribution,
                )?;
                outcome_project = outcome.sync_project;
                outcome.files
            }
            Eco::Cargo => cargo_delegate(
                &store,
                activity,
                platform,
                &project,
                request.verb,
                &texts,
                request.dev,
                attribution,
            )?,
            Eco::Go => go_delegate(
                &store,
                activity,
                platform,
                &project,
                request.verb,
                &texts,
                request.dev,
                attribution,
            )?,
            Eco::Ruby => ruby_delegate(
                &store,
                activity,
                platform,
                &project,
                request.verb,
                &texts,
                request.dev,
                attribution,
            )?,
            Eco::Elixir => elixir_delegate(
                &store,
                activity,
                platform,
                &project,
                request.verb,
                &texts,
                attribution,
            )?,
            Eco::Dotnet => dotnet_refuse(request.verb, &texts, attribution)?,
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

fn sync_root_for(eco: Eco, project: &Path) -> io::Result<PathBuf> {
    match eco {
        Eco::Node => Ok(match node_lock_for(project)? {
            NodeLock::Own { root, .. } => root,
            NodeLock::PnpmWorkspaceMember { root } => root,
            NodeLock::UnlistedUnderPnpmWorkspace { .. } => project.to_path_buf(),
        }),
        _ => Ok(project.to_path_buf()),
    }
}

fn reject_mixed_sync_roots(
    verb: Verb,
    project: &Path,
    groups: &[(Eco, Vec<Spec>)],
) -> io::Result<()> {
    let mut roots = Vec::new();
    for (eco, _) in groups {
        let root = sync_root_for(*eco, project)?;
        if !roots.contains(&root) {
            roots.push(root);
        }
    }
    if roots.len() > 1 {
        return Err(other(format!(
            "dependency edit spans multiple project roots: {}; run the two {} separately",
            roots
                .iter()
                .map(|root| root.display().to_string())
                .collect::<Vec<_>>()
                .join(" and "),
            match verb {
                Verb::Add => "adds",
                Verb::Remove => "removes",
                Verb::Update => "updates",
            }
        )));
    }
    Ok(())
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
    /// convention): tog edits the .in and recompiles.
    PipCompile,
    /// A plain requirements file tog re-locks into requirements.lock.txt.
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
    activity: &StoreActivity,
    platform: Platform,
    project: &Path,
    verb: Verb,
    texts: &[String],
    names: &[String],
    dev: bool,
    attribution: &mut policy::Attribution,
) -> io::Result<Vec<String>> {
    validate_delegate_specs(texts)?;
    let shape = python_shape(project)?;
    match shape {
        PyShape::Poetry => Err(other(match verb {
            Verb::Add => format!(
                "this is a Poetry project and Poetry is not a pinned tool: add {} under [tool.poetry.dependencies] in pyproject.toml (or run 'poetry add {}'), then 'tog'",
                python_line(texts),
                texts.join(" ")
            ),
            Verb::Remove => format!(
                "this is a Poetry project: remove {} from [tool.poetry.dependencies] in pyproject.toml (or run 'poetry remove {}'), then 'tog'",
                names.join(", "),
                names.join(" ")
            ),
            Verb::Update => "this is a Poetry project: run 'poetry update' (or 'poetry lock'), then 'tog'".to_string(),
        })),
        PyShape::Pdm => Err(other(format!(
            "this is a PDM project (pdm.lock) and PDM is not a pinned tool: run 'pdm {} {}', then 'tog'",
            match verb {
                Verb::Add => "add",
                Verb::Remove => "remove",
                Verb::Update => "update",
            },
            texts.join(" ")
        ))),
        PyShape::Setup => Err(other(match verb {
            Verb::Add => format!(
                "dependencies live in install_requires here: add {} to setup.cfg [options] install_requires (or setup.py), then 'tog'",
                python_line(texts)
            ),
            Verb::Remove => format!(
                "dependencies live in install_requires here: remove {} from setup.cfg / setup.py, then 'tog'",
                names.join(", ")
            ),
            Verb::Update => "install_requires projects re-lock on every sync (there is no separate lock to update); loosen the constraint in setup.cfg / setup.py, then 'tog'".to_string(),
        })),
        PyShape::RequirementsDir => Err(other(format!(
            "dependencies live under requirements/ here: edit the file that applies (requirements/common.txt, base.txt, ...) to {} {}, then 'tog'",
            match verb {
                Verb::Add => "add",
                Verb::Remove => "remove",
                Verb::Update => "update",
            },
            texts.join(" ")
        ))),
        PyShape::Uv => python_uv(store, activity, platform, project, verb, texts, dev, attribution),
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
            uv_compile(
                store,
                activity,
                platform,
                project,
                &input,
                &output,
                &upgrade,
                attribution,
            )?;
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
                uv_compile(
                    store,
                    activity,
                    platform,
                    project,
                    &path,
                    &lock,
                    &upgrade_flags(verb, names),
                    attribution,
                )?;
                files.push("requirements.lock.txt".to_string());
            } else {
                // The ordinary sync re-locks when the source hash changes; a
                // stale stamp from an unchanged source (update with no lock
                // yet) is cleared so sync resolves afresh. Through the held
                // project descriptor, so a symlinked `.tog` cannot redirect
                // the unlink outside the project.
                ProjectRoot::open(project)?.remove_file(Path::new(".tog/lock-source.hash"))?;
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
    // record.  Editing whole records, not physical lines, is what keeps a
    // remove from leaving orphaned hash constraints behind.
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
            ".{file_name}.tog-edit-{stamp}-{}-{counter}",
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
    activity: &StoreActivity,
    platform: Platform,
    project: &Path,
) -> io::Result<(Command, String)> {
    let toolchain = selected_toolchain(platform, project, "python")?;
    let version = toolchain.version("cpython")?.to_string();
    let uv = python::realize_uv(store, activity, platform, &toolchain)?.join("uv");
    let interpreter = python::realize_runtime(store, activity, platform, &toolchain)?;
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
    Ok((command, version))
}

fn run_inherited(activity: &StoreActivity, mut command: Command, what: &str) -> io::Result<()> {
    ui::trace_command(&command);
    let status = crate::kernel::supervise::status(&mut command, activity)
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
    activity: &StoreActivity,
    platform: Platform,
    project: &Path,
    input: &Path,
    output: &Path,
    extra: &[String],
    _attribution: &mut policy::Attribution,
) -> io::Result<()> {
    let (mut command, version) = uv_command(store, activity, platform, project)?;
    command
        .args(["pip", "compile"])
        .arg(input)
        .arg("--generate-hashes");
    if !ui::verbose() {
        command.arg("--quiet");
    }
    command
        .args(["--python-version", &version])
        .args(["--index-url", "https://pypi.org/simple"])
        .arg("-o")
        .arg(output)
        .args(extra);
    run_inherited(activity, command, "store uv pip compile")
}

fn python_uv(
    store: &Store,
    activity: &StoreActivity,
    platform: Platform,
    project: &Path,
    verb: Verb,
    texts: &[String],
    dev: bool,
    _attribution: &mut policy::Attribution,
) -> io::Result<Vec<String>> {
    validate_delegate_specs(texts)?;
    let (mut command, _) = uv_command(store, activity, platform, project)?;
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
    run_inherited(activity, command, "store uv")?;
    Ok(vec!["pyproject.toml".to_string(), "uv.lock".to_string()])
}

// ---------------------------------------------------------------------------
// Node

#[derive(Debug, Clone, PartialEq, Eq)]
enum NodePackageManager {
    Pnpm {
        version: String,
        corepack_hash: Option<xrun::CorepackHash>,
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

    fn corepack_hash(&self) -> Option<&xrun::CorepackHash> {
        let Self::Pnpm { corepack_hash, .. } = self;
        corepack_hash.as_ref()
    }

    fn executable(&self) -> &'static str {
        "pnpm"
    }
}

/// Split a `packageManager` version off its Corepack `+<algo>.<hex>` hash
/// suffix. The suffix is diagnosed on its own terms: an unknown algorithm
/// names the algorithm and the supported set rather than blaming a version
/// that is already exact.
fn package_manager_version(
    value: &str,
    package_json: &Path,
) -> io::Result<(String, Option<xrun::CorepackHash>)> {
    let (version, suffix) = match value.split_once('+') {
        Some((version, suffix)) => (version, Some(suffix)),
        None => (value, None),
    };
    let hash = match suffix {
        None => None,
        Some(suffix) => {
            let (algo, hex) = suffix.split_once('.').ok_or_else(|| {
                other(format!(
                    "{}: packageManager hash suffix must be +<algo>.<hex>, found \"+{suffix}\"; supported algorithms are {}",
                    package_json.display(),
                    xrun::CorepackAlgo::SUPPORTED
                ))
            })?;
            let parsed = xrun::CorepackAlgo::parse(algo).ok_or_else(|| {
                other(format!(
                    "{}: packageManager hash algorithm {algo:?} is not supported; tog verifies {}; drop the suffix or re-pin with one of those",
                    package_json.display(),
                    xrun::CorepackAlgo::SUPPORTED
                ))
            })?;
            if hex.len() != parsed.hex_len() || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(other(format!(
                    "{}: packageManager has a malformed {} hash",
                    package_json.display(),
                    parsed.name()
                )));
            }
            Some(xrun::CorepackHash {
                algo: parsed,
                hex: hex.to_ascii_lowercase(),
            })
        }
    };
    if !xrun::is_exact_version(version) {
        return Err(other(format!(
            "{}: packageManager version must be an exact release such as pnpm@9.12.3 (a prerelease suffix is allowed)",
            package_json.display()
        )));
    }
    Ok((version.to_string(), hash))
}

fn parse_package_manager_value(value: &str, package_json: &Path) -> io::Result<NodePackageManager> {
    let version = value.strip_prefix("pnpm@").ok_or_else(|| {
        other(format!(
            "{}: packageManager must be pnpm@<exact-version>, found {value:?}",
            package_json.display()
        ))
    })?;
    let (version, corepack_hash) = package_manager_version(version, package_json)?;
    Ok(NodePackageManager::Pnpm {
        version,
        corepack_hash,
    })
}

fn pnpm_lock_format(lock_text: &str) -> Option<String> {
    lock_text
        .lines()
        .find_map(|line| {
            line.trim()
                .strip_prefix("lockfileVersion:")
                .map(|version| version.trim().trim_matches(['\'', '"']))
        })
        .filter(|version| !version.is_empty())
        .map(str::to_string)
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
        let format = pnpm_lock_format(lock_text)
            .map(|format| format!(" pnpm-lock.yaml is lockfile format {format};"))
            .unwrap_or_default();
        other(format!(
            "{}: packageManager is required;{format} set packageManager to the exact pnpm version your team runs, e.g. from `pnpm --version`",
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

/// What an ancestor `pnpm-lock.yaml` says about a project below it.
///
/// `pnpm-workspace.yaml` existing is not the question: since pnpm 10 that file
/// is also the project-level settings file, so `pnpm config set
/// --location=project` writes one in a repository that has no workspace at
/// all. The lock's `importers` list is the authority pnpm itself produced.
#[derive(Debug)]
enum PnpmMembership {
    Listed,
    UnlistedInWorkspace,
    NotAWorkspace,
}

fn pnpm_membership(root: &Path, project: &Path) -> io::Result<PnpmMembership> {
    let canonical_root = root.canonicalize()?;
    let canonical_project = project.canonicalize()?;
    let relative = canonical_project
        .strip_prefix(&canonical_root)
        .map_err(|_| {
            other(format!(
                "project {} is outside pnpm workspace root {}",
                canonical_project.display(),
                canonical_root.display()
            ))
        })?;
    let mut key = String::new();
    for component in relative.components() {
        let std::path::Component::Normal(part) = component else {
            return Err(other(format!(
                "project {} is not a plain path below pnpm workspace root {}",
                canonical_project.display(),
                canonical_root.display()
            )));
        };
        let part = part.to_str().ok_or_else(|| {
            other(format!(
                "project {} has a path component that is not UTF-8",
                canonical_project.display()
            ))
        })?;
        if !key.is_empty() {
            key.push('/');
        }
        key.push_str(&part.replace('\\', "/"));
    }
    if key.is_empty() {
        key.push('.');
    }
    let lock_path = root.join("pnpm-lock.yaml");
    let text = fs::read_to_string(&lock_path)
        .map_err(|error| other(format!("read {}: {error}", lock_path.display())))?;
    let importers = crate::tailors::node::lock_import::pnpm_lock_importers(&text).map_err(|error| {
        other(format!(
            "{}: {error}; tog reads workspace membership from this file, so it must parse. If it is the result of an unresolved merge conflict, resolve the conflict or delete the file and run 'pnpm install' in {} to regenerate it, then run tog again",
            lock_path.display(),
            root.display()
        ))
    })?;
    if importers.iter().any(|importer| importer == &key) {
        return Ok(PnpmMembership::Listed);
    }
    if importers.iter().any(|importer| importer != ".") {
        return Ok(PnpmMembership::UnlistedInWorkspace);
    }
    Ok(PnpmMembership::NotAWorkspace)
}

/// Select the lockfile to edit. A lockfile in the project itself wins in the
/// same order as sync. Only a pnpm workspace root may be inherited, and only
/// when that root's `pnpm-lock.yaml` lists the project among its importers.
/// Any other ancestor lock is a boundary.
///
/// The third variant is not an advisory flag a caller may drop: tog
/// cannot tell a member added since the last install from a project the
/// workspace deliberately excludes, so each caller has to say what it does
/// about that, and anything that would write a lockfile must refuse.
enum NodeLock {
    Own { name: String, root: PathBuf },
    PnpmWorkspaceMember { root: PathBuf },
    UnlistedUnderPnpmWorkspace { workspace_root: PathBuf },
}

fn node_lock_for(project: &Path) -> io::Result<NodeLock> {
    let own = |name: &str| NodeLock::Own {
        name: name.to_string(),
        root: project.to_path_buf(),
    };
    if let Some(lock_name) = node_lock_at(project) {
        return Ok(own(lock_name));
    }
    if project.join(".tog").is_dir() {
        return Ok(own("package-lock.json"));
    }
    for ancestor in project.ancestors().skip(1) {
        if let Some(lock_name) = node_lock_at(ancestor) {
            if lock_name != "pnpm-lock.yaml" {
                break;
            }
            match pnpm_membership(ancestor, project)? {
                PnpmMembership::Listed => {
                    return Ok(NodeLock::PnpmWorkspaceMember {
                        root: ancestor.to_path_buf(),
                    });
                }
                PnpmMembership::UnlistedInWorkspace => {
                    return Ok(NodeLock::UnlistedUnderPnpmWorkspace {
                        workspace_root: ancestor.to_path_buf(),
                    });
                }
                PnpmMembership::NotAWorkspace => break,
            }
        }
        if ancestor.join(".tog").is_dir() {
            break;
        }
    }
    Ok(own("package-lock.json"))
}

fn is_yarn_berry(root: &Path) -> bool {
    if root.join(".yarnrc.yml").is_file() {
        return true;
    }
    let Ok(text) = fs::read_to_string(root.join("package.json")) else {
        return false;
    };
    let Ok(package) = serde_json::from_str::<serde_json::Value>(&text) else {
        return false;
    };
    let Some(value) = package
        .get("packageManager")
        .and_then(|value| value.as_str())
    else {
        return false;
    };
    let Some(version) = value.strip_prefix("yarn@") else {
        return false;
    };
    version
        .split(['.', '-', '+'])
        .next()
        .and_then(|major| major.parse::<u64>().ok())
        .is_some_and(|major| major >= 2)
}

fn yarn_refusal(root: &Path, verb: Verb, texts: &[String], dev: bool) -> io::Error {
    if is_yarn_berry(root) {
        return other(
            "this project uses Yarn Berry; Berry cache checksums are not npm tarball integrity values; convert with 'npm install --package-lock-only' or 'pnpm install --lockfile-only', then 'tog'",
        );
    }
    let tool_verb = verb.command();
    other(format!(
        "this project is locked by yarn (yarn.lock) and yarn is not a pinned tool; run 'yarn {tool_verb}{}{}', then 'tog' (it imports yarn.lock)",
        if dev && verb == Verb::Add { " -D" } else { "" },
        texts.iter().map(|text| format!(" {text}")).collect::<String>()
    ))
}

fn node_delegate_args(
    verb: Verb,
    texts: &[String],
    dev: bool,
    workspace_root: bool,
    scratch: &PnpmScratch,
) -> Vec<String> {
    let mut args = vec![verb.command().to_string()];
    args.push("--lockfile-only".into());
    // Match the npm branch's defence in depth: `--lockfile-only` should mean
    // nothing installs and no lifecycle script runs, but pnpm still runs
    // `prepare` for git-URL dependencies while resolving. pnpm's `remove`
    // parser rejects `--ignore-scripts` outright ("Unknown option:
    // 'ignore-scripts'"), so the flag goes only on the verbs whose parser
    // accepts it; `npm_config_ignore_scripts` in the delegate's environment
    // (see `node`) is what covers all three.
    if verb != Verb::Remove {
        args.push("--ignore-scripts".into());
    }
    args.extend(["--reporter", "append-only"].map(str::to_string));
    // Keep pnpm's modules state out of the user's project (see
    // `PnpmScratch`). `--config.<name>=<value>` is the spelling every verb's
    // parser accepts; `remove` and `update` reject `--modules-dir` as a flag.
    args.push("--config.enable-modules-dir=false".into());
    // `enable-modules-dir=false` only means "do not link into the modules
    // directory" for the isolated linker. A project `.npmrc` carrying
    // `node-linker=hoisted` makes the delegate a real installer again: it
    // downloads packages and rewrites the user's `node_modules`, replacing
    // symlinks with copied directories. `node-linker=pnp` fails with a raw
    // pnpm stack trace. Force the linker so no project file can pick either.
    args.push("--config.node-linker=isolated".into());
    args.push(format!("--config.modules-dir={}", scratch.modules_dir));
    args.push(format!(
        "--config.virtual-store-dir={}",
        scratch.virtual_store_dir
    ));
    // pnpm falls back to `~/.pnpm-store` whenever its default store would
    // land on a different filesystem from the project: outside the project,
    // outside the tog store, and never reclaimed by `gc`.
    args.push(format!("--config.store-dir={}", scratch.store_dir));
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

/// Where pnpm keeps its modules state during an edit: a per-run stage
/// under `<store>/tmp`, never the user's project.
///
/// Even with `--lockfile-only`, pnpm's modules directory is live: at a
/// workspace root `add -w --lockfile-only` performs a full install, every
/// verb reads `node_modules/.modules.yaml` and refuses with
/// `ERR_PNPM_UNEXPECTED_STORE` when the store recorded there is not the one
/// it is given, and the workspace path deletes `<virtual-store-dir>/lock.yaml`
/// when the current lockfile is empty. Three settings, all honoured by
/// `add`, `remove`, and `update` of pnpm 9.12.3 (verified against the real
/// binary; `tests/deps_e2e.rs::pnpm_edits_leave_an_installed_project_untouched`
/// keeps proving it), move all of that out of the project:
/// `enable-modules-dir=false` links nothing, `modules-dir` decides where
/// `.modules.yaml` is looked for, and `virtual-store-dir` decides where the
/// current lockfile lives. pnpm joins both paths onto a project directory
/// (`path.join`, so an absolute value would land inside the project), hence
/// the relative spellings. Nothing is created at either path; the stage
/// exists so the paths resolve somewhere tog owns, and it is removed when
/// the delegate returns (a leftover has the `stage-` name `gc::sweep_stages`
/// reclaims).
struct PnpmScratch {
    /// `--config.modules-dir`, relative to the project pnpm runs in.
    ///
    /// pnpm joins this onto *every* importer's own directory, and one
    /// relative path cannot escape the project from importers at differing
    /// depths: computed for a workspace root, it lands back inside the
    /// project for any deeper member. What keeps the project untouched is
    /// therefore not this path but `enable-modules-dir=false` together with
    /// `node-linker=isolated` — with both, pnpm creates no importer
    /// `node_modules` at all, and this path only ever names a
    /// `.modules.yaml` to read. Remove either flag and the path alone will
    /// not save you.
    modules_dir: String,
    /// `--config.virtual-store-dir`, relative to the lock root, which is what
    /// pnpm resolves it against.
    virtual_store_dir: String,
    /// `--config.store-dir`. Absolute: pnpm resolves the store directory
    /// against the cwd rather than joining it onto an importer, so an
    /// absolute path is both safe here and the only spelling that pins the
    /// store no matter which directory the delegate runs in.
    store_dir: String,
}

fn pnpm_scratch(stage: &Path, project: &Path, lock_root: &Path) -> io::Result<PnpmScratch> {
    let stage = stage.canonicalize()?;
    let project = project.canonicalize()?;
    let lock_root = lock_root.canonicalize()?;
    let modules = stage.join("modules");
    Ok(PnpmScratch {
        modules_dir: relative_path(&project, &modules)
            .to_string_lossy()
            .into_owned(),
        virtual_store_dir: relative_path(&lock_root, &modules.join(".pnpm"))
            .to_string_lossy()
            .into_owned(),
        store_dir: stage.join("pnpm-store").to_string_lossy().into_owned(),
    })
}

/// `to` expressed relative to the directory `from`; both must be absolute and
/// free of `..` (canonical), so the answer is a lexical prefix strip.
fn relative_path(from: &Path, to: &Path) -> PathBuf {
    let from: Vec<_> = from.components().collect();
    let to: Vec<_> = to.components().collect();
    let common = from
        .iter()
        .zip(to.iter())
        .take_while(|(a, b)| a == b)
        .count();
    let mut out = PathBuf::new();
    for _ in common..from.len() {
        out.push("..");
    }
    for component in &to[common..] {
        out.push(component);
    }
    out
}

struct NodeEdit {
    files: Vec<String>,
    sync_project: PathBuf,
}

fn node(
    store: &Store,
    activity: &StoreActivity,
    platform: Platform,
    project: &Path,
    verb: Verb,
    texts: &[String],
    dev: bool,
    attribution: &mut policy::Attribution,
) -> io::Result<NodeEdit> {
    validate_delegate_specs(texts)?;
    let (lock_name, lock_root) = match node_lock_for(project)? {
        NodeLock::Own { name, root } => (name, root),
        NodeLock::PnpmWorkspaceMember { root } => ("pnpm-lock.yaml".to_string(), root),
        NodeLock::UnlistedUnderPnpmWorkspace { workspace_root } => {
            return Err(other(format!(
                "{} sits under the pnpm workspace {} but {} does not list it as an importer, so tog cannot tell whether it is a workspace member. If it is a member you added since the last install, run 'pnpm install' in {} and then run tog again. If it is deliberately outside the workspace, put a .tog directory in {} to make it its own root. Tog refuses rather than write a package-lock.json inside a pnpm workspace",
                project.display(),
                workspace_root.display(),
                workspace_root.join("pnpm-lock.yaml").display(),
                workspace_root.display(),
                project.display()
            )));
        }
    };
    if lock_name == "package-lock.json" {
        let node_obj = node::realize_runtime(
            store,
            activity,
            platform,
            &selected_toolchain(platform, project, "node")?,
        )?;
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
        run_inherited(activity, command, "store npm")?;
        return Ok(NodeEdit {
            files: vec!["package.json".into(), "package-lock.json".into()],
            sync_project: project.to_path_buf(),
        });
    }
    let lock_text = fs::read_to_string(lock_root.join(&lock_name))?;
    if lock_name == "yarn.lock" {
        return Err(yarn_refusal(&lock_root, verb, texts, dev));
    }
    let manager = node_package_manager(&lock_root, &lock_text)?;
    let mut node_attribution = attribution.nested("node")?;
    let (tool_root, _x_lock, realized) = xrun::realize_node_tool(
        store,
        activity,
        platform,
        &lock_root,
        manager.name(),
        manager.version(),
        manager.corepack_hash(),
        &mut node_attribution,
    )?;
    if realized {
        node_attribution.finish(true)?;
    } else {
        node_attribution.discard();
    }
    let node_obj = node::realize_runtime(
        store,
        activity,
        platform,
        &selected_toolchain(platform, project, "node")?,
    )?;
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
    // One per-run stage holds pnpm's isolated HOME/XDG root (so pnpm never
    // reads or writes the user's pnpm config, store or registry metadata
    // cache) and the scratch its modules state is pointed at (see
    // `PnpmScratch`). It is removed when the delegate returns; a leftover
    // from a killed run carries the `stage-` name `tog gc` sweeps.
    let stage = store.stage_with_activity(activity)?;
    let package_path = project.join("package.json");
    let result = (|| -> io::Result<()> {
        let scratch = pnpm_scratch(&stage, project, &lock_root)?;
        let args = node_delegate_args(
            verb,
            texts,
            dev,
            lock_name == "pnpm-lock.yaml"
                && project == lock_root
                && lock_root.join("pnpm-workspace.yaml").is_file(),
            &scratch,
        );
        let pnpm_home_dir = stage.join("home");
        let pnpm_config = pnpm_home_dir.join("xdg-config");
        let pnpm_data = pnpm_home_dir.join("xdg-data");
        let pnpm_cache = pnpm_home_dir.join("xdg-cache");
        let pnpm_state = pnpm_home_dir.join("xdg-state");
        fs::create_dir_all(&pnpm_home_dir)?;
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
        // `npm_config_ignore_scripts` is set after the `npm_config_` strip
        // (which `force_env` applies case-insensitively, the way npm and pnpm
        // read `/^npm_config_/i`), so it is tog's value, not the user's.
        // It is the only way to say "run no lifecycle script" to
        // `pnpm remove`, whose parser rejects the `--ignore-scripts` flag;
        // `add` and `update` carry the flag too, and `--lockfile-only`
        // itself forces `ignoreScripts` inside pnpm's install options.
        sandbox::force_env(
            &mut command,
            &["npm_config_", "PNPM_", "YARN_", "COREPACK_"],
            &["NODE_OPTIONS"],
            &[
                ("CI".into(), "1".into()),
                ("npm_config_ignore_scripts".into(), "true".into()),
            ],
        );
        run_inherited(activity, command, &format!("store {}", manager.name()))?;
        Ok(())
    })();
    let _ = crate::kernel::store::remove_tree(&stage);
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
    activity: &StoreActivity,
    platform: Platform,
    project: &Path,
    verb: Verb,
    texts: &[String],
    dev: bool,
    _attribution: &mut policy::Attribution,
) -> io::Result<Vec<String>> {
    validate_delegate_specs(texts)?;
    // `cargo add` and `cargo remove` need only cargo, so the edit runs on
    // the base toolchain of the project's selection. The components and
    // targets the toolchain file asks for are provisioned by the sync that
    // follows.
    let rust_obj = cargo::realize_runtime(
        store,
        activity,
        platform,
        &selected_toolchain(platform, project, "cargo")?,
    )?;
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
    run_inherited(activity, command, "store cargo")?;
    Ok(vec!["Cargo.toml".to_string(), "Cargo.lock".to_string()])
}

// ---------------------------------------------------------------------------
// Go

fn go_delegate(
    store: &Store,
    activity: &StoreActivity,
    platform: Platform,
    project: &Path,
    verb: Verb,
    texts: &[String],
    dev: bool,
    _attribution: &mut policy::Attribution,
) -> io::Result<Vec<String>> {
    validate_delegate_specs(texts)?;
    if dev {
        return Err(other(
            "--dev has no meaning in Go (one dependency set per module)",
        ));
    }
    let go_obj = go::realize_runtime(
        store,
        activity,
        platform,
        &selected_toolchain(platform, project, "go")?,
    )?;
    let scratch = store.stage_with_activity(activity)?;
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
    let result = go::run_checked(activity, &go_obj, project, &scratch, false, &refs);
    let _ = crate::kernel::store::remove_tree(&scratch);
    result?;
    Ok(vec!["go.mod".to_string(), "go.sum".to_string()])
}

// ---------------------------------------------------------------------------
// Ruby

fn ruby_delegate(
    store: &Store,
    activity: &StoreActivity,
    platform: Platform,
    project: &Path,
    verb: Verb,
    texts: &[String],
    dev: bool,
    _attribution: &mut policy::Attribution,
) -> io::Result<Vec<String>> {
    validate_delegate_specs(texts)?;
    let ruby_obj = ruby::realize_runtime(
        store,
        activity,
        platform,
        &selected_toolchain(platform, project, "ruby")?,
    )?;
    let scratch = store.stage_with_activity(activity)?;
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
                    ruby::run_checked(activity, &ruby_obj, project, &scratch, &args)?;
                }
                Ok(())
            }
            Verb::Remove => {
                let mut args = vec!["bundle", "remove"];
                args.extend(texts.iter().map(String::as_str));
                ruby::run_checked(activity, &ruby_obj, project, &scratch, &args)
            }
            Verb::Update => {
                let mut args = vec!["bundle", "update"];
                if texts.is_empty() {
                    args.push("--all");
                }
                args.extend(texts.iter().map(String::as_str));
                ruby::run_checked(activity, &ruby_obj, project, &scratch, &args)
            }
        }
    })();
    let _ = crate::kernel::store::remove_tree(&scratch);
    result?;
    Ok(vec!["Gemfile".to_string(), "Gemfile.lock".to_string()])
}

// ---------------------------------------------------------------------------
// Elixir

fn elixir_delegate(
    store: &Store,
    activity: &StoreActivity,
    platform: Platform,
    project: &Path,
    verb: Verb,
    texts: &[String],
    _attribution: &mut policy::Attribution,
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
                "there is no 'mix add': put {lines} in the deps list of mix.exs, then 'tog' (it runs mix deps.get and re-locks)"
            )))
        }
        Verb::Remove => Err(other(format!(
            "there is no 'mix remove': delete {} from the deps list of mix.exs, then 'tog'",
            texts
                .iter()
                .map(|name| format!("{{:{name}, ...}}"))
                .collect::<Vec<_>>()
                .join(", ")
        ))),
        Verb::Update => {
            let beam = elixir::realize_runtime(
                store,
                activity,
                platform,
                &selected_toolchain(platform, project, "elixir")?,
            )?;
            let scratch = store.stage_with_activity(activity)?;
            let mut args = vec!["mix", "deps.update"];
            if texts.is_empty() {
                args.push("--all");
            }
            args.extend(texts.iter().map(String::as_str));
            let result = elixir::run_checked(activity, &beam, project, &scratch, false, &args);
            let _ = crate::kernel::store::remove_tree(&scratch);
            result?;
            Ok(vec!["mix.lock".to_string()])
        }
    }
}

// ---------------------------------------------------------------------------
// .NET

fn dotnet_refuse(
    verb: Verb,
    texts: &[String],
    _attribution: &mut policy::Attribution,
) -> io::Result<Vec<String>> {
    validate_delegate_specs(texts)?;
    let names = texts.join(" ");
    Err(other(match verb {
        Verb::Add => format!(
            "tog never evaluates MSBuild outside the sandbox, and 'dotnet add package' restores: run 'dotnet add package {names}' then 'dotnet restore --force-evaluate' with your own SDK, commit packages.lock.json, then 'tog'"
        ),
        Verb::Remove => format!(
            "run 'dotnet remove package {names}' then 'dotnet restore --force-evaluate' with your own SDK, commit packages.lock.json, then 'tog'"
        ),
        Verb::Update => "edit the PackageReference versions, run 'dotnet restore --force-evaluate' with your own SDK, commit packages.lock.json, then 'tog'".to_string(),
    }))
}

/// `add` / `remove` / `update`: delegate the edit, report it, then the
/// ordinary sync in the project the edit landed in.
pub fn run(ctx: &Context, request: Request, no_sync: bool) -> io::Result<()> {
    let cwd = project_dir();
    // Dependency edits ensure pinned tools before the ordinary sync. Load
    // the policy chain first: a cached toolchain object read before it
    // would fix the process policy without the policy files, and their
    // deny entries would not apply to the edit or the sync after it.
    policy::init(&cwd)?;
    let mut edit_attribution = edit_attribution()?;
    let outcome = edit(
        ctx.platform,
        &ctx.activity,
        &cwd,
        request,
        &mut edit_attribution,
    )?;
    for line in &outcome.lines {
        ui::note(line);
    }
    if no_sync {
        ui::note("--no-sync: review the change, then run 'tog'");
        edit_attribution.discard();
        return Ok(());
    }
    if outcome.project != cwd {
        std::env::set_current_dir(&outcome.project)?;
        ui::trace(&format!("syncing in {}", outcome.project.display()));
    }
    // The edit owns its exceptions. Sync must open a fresh ecosystem scope.
    edit_attribution.discard();
    sync::run(ctx, false)
}

/// Open the dependency edit's attribution scope before the edit can record.
///
/// `edit` records exceptions of its own, outside any ecosystem's closure: on
/// a warm store every `ensure_*_for` replays cached-object exceptions
/// through `policy::check_cached`. Those belong to the edit, not to whichever
/// ecosystem `sync` happens to realize first. `discard` clears them before
/// sync; `Drop` covers errors, panics, and `--no-sync`. Enforcement already
/// happened during the edit, and the owning tailor re-records the applicable
/// exception inside its own scope during the sync that follows.
fn edit_attribution() -> io::Result<policy::Attribution> {
    policy::Attribution::open("dependency-edit")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::testutil::TempDir;
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
        let option = "looks like a tool option";
        let control = "must not contain CR, LF, or NUL";
        for (text, needle) in [
            ("", "must not be empty"),
            ("   ", "must not be empty"),
            (" requests", "must not begin or end with whitespace"),
            ("--prefix=/tmp/elsewhere", option),
            ("npm:--prefix=/tmp/elsewhere", option),
            ("cargo:--manifest-path=/tmp/Cargo.toml", option),
            ("requests>=-1", "contains an option-shaped constraint"),
            ("pkg@--x", "contains an option-shaped constraint"),
            ("npm:\nreact", control),
            ("requests\0evil", control),
        ] {
            let error = validate_spec(text).expect_err(&format!("accepted unsafe spec {text:?}"));
            assert!(error.to_string().contains(needle), "{text:?}: {error}");
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
                corepack_hash: None,
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
                corepack_hash: Some(xrun::CorepackHash {
                    algo: xrun::CorepackAlgo::Sha224,
                    hex: "a".repeat(56),
                }),
            }
        );
        let garbage =
            parse_package_manager_value("not-a-package-manager", package_json).unwrap_err();
        assert!(garbage.to_string().contains("packageManager"), "{garbage}");
        let malformed_hash =
            parse_package_manager_value("pnpm@9.1.2+sha224.not-a-hash", package_json).unwrap_err();
        assert!(malformed_hash.to_string().contains("malformed sha224"));
    }

    /// Corepack has written three hash algorithms over its life; every one it
    /// writes is a pin, so none of them may be misdiagnosed as an inexact
    /// version. An algorithm tog cannot verify is refused by name.
    #[test]
    fn corepack_hash_suffixes_accept_every_supported_algorithm() {
        let package_json = Path::new("package.json");
        for (algo, width) in [
            (xrun::CorepackAlgo::Sha224, 56),
            (xrun::CorepackAlgo::Sha256, 64),
            (xrun::CorepackAlgo::Sha512, 128),
        ] {
            let value = format!("pnpm@9.15.4+{}.{}", algo.name(), "B".repeat(width));
            assert_eq!(
                parse_package_manager_value(&value, package_json).unwrap(),
                NodePackageManager::Pnpm {
                    version: "9.15.4".into(),
                    corepack_hash: Some(xrun::CorepackHash {
                        algo,
                        hex: "b".repeat(width),
                    }),
                },
                "rejected {value}"
            );
            // The right hex for the wrong algorithm is a malformed hash, not a
            // silently accepted one.
            let short = format!("pnpm@9.15.4+{}.{}", algo.name(), "b".repeat(width - 2));
            let error = parse_package_manager_value(&short, package_json).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains(&format!("malformed {} hash", algo.name())),
                "{error}"
            );
        }

        let unknown = parse_package_manager_value(
            &format!("pnpm@9.15.4+sha1.{}", "c".repeat(40)),
            package_json,
        )
        .unwrap_err()
        .to_string();
        assert!(unknown.contains("\"sha1\""), "{unknown}");
        assert!(unknown.contains("sha224, sha256, sha512"), "{unknown}");
        assert!(!unknown.contains("exact release"), "{unknown}");

        let shapeless = parse_package_manager_value("pnpm@9.15.4+deadbeef", package_json)
            .unwrap_err()
            .to_string();
        assert!(shapeless.contains("+<algo>.<hex>"), "{shapeless}");
        assert!(!shapeless.contains("exact release"), "{shapeless}");
    }

    #[test]
    fn missing_pnpm_package_manager_names_lock_format_without_floating_suggestion() {
        let scratch = TempDir::named("node-package-manager");
        let root = scratch.0.clone();
        fs::write(root.join("package.json"), "{}\n").unwrap();
        let missing = node_package_manager(&root, "lockfileVersion: '9.0'\n").unwrap_err();
        let missing = missing.to_string();
        assert!(
            missing.contains(
                "pnpm-lock.yaml is lockfile format 9.0; set packageManager to the exact pnpm version your team runs, e.g. from `pnpm --version`"
            ),
            "{missing}"
        );
        assert!(!missing.contains("pnpm major 9"), "{missing}");
    }

    /// `pnpm-lock.yaml` decides membership, so two shapes a glob-based
    /// reading would send down the npm branch — writing a stray
    /// `package-lock.json` inside a pnpm workspace — resolve correctly: an
    /// alternation group, which pnpm's glob engine supports and tog's
    /// matcher does not, and a block sequence at the parent key's own
    /// indent, which is ordinary hand-written YAML that tog's
    /// lockfile-shaped parser rejects.
    #[test]
    fn workspace_membership_comes_from_the_lock_not_the_glob() {
        let scratch = TempDir::named("ws-importers");
        let root = scratch.0.clone();
        let member = root.join("apps/web");
        fs::create_dir_all(&member).unwrap();
        fs::write(
            root.join("pnpm-lock.yaml"),
            "lockfileVersion: '9.0'\n\nimporters:\n\n  .: {}\n\n  apps/web: {}\n",
        )
        .unwrap();
        // Both hostile-to-tog shapes at once: alternation, at indent 0.
        fs::write(
            root.join("pnpm-workspace.yaml"),
            "packages:\n- '(apps|libs)/*'\n",
        )
        .unwrap();
        assert!(
            matches!(
                pnpm_membership(&root, &member).unwrap(),
                PnpmMembership::Listed
            ),
            "a member the lock enumerates was not recognised"
        );
        assert!(
            matches!(
                pnpm_membership(&root, &root).unwrap(),
                PnpmMembership::Listed
            ),
            "the workspace root itself was not recognised"
        );

        let stranger = root.join("apps/other");
        fs::create_dir_all(&stranger).unwrap();
        assert!(
            matches!(
                pnpm_membership(&root, &stranger).unwrap(),
                PnpmMembership::UnlistedInWorkspace
            ),
            "a directory the lock does not enumerate was treated as a member"
        );

        fs::write(
            root.join("pnpm-lock.yaml"),
            "lockfileVersion: '9.0'\n\t bad\n",
        )
        .unwrap();
        let error = pnpm_membership(&root, &member).unwrap_err();
        assert!(error.to_string().contains("pnpm install"), "{error}");
    }

    #[test]
    fn node_delegate_argv_is_delimited_and_workspace_aware() {
        let scratch = PnpmScratch {
            modules_dir: "../../store/tmp/stage-1/modules".into(),
            virtual_store_dir: "../store/tmp/stage-1/modules/.pnpm".into(),
            store_dir: "/store/tmp/stage-1/pnpm-store".into(),
        };
        let args = node_delegate_args(
            Verb::Add,
            &["@scope/pkg@1.2.3".into()],
            true,
            true,
            &scratch,
        );
        assert_eq!(
            args,
            vec![
                "add",
                "--lockfile-only",
                "--ignore-scripts",
                "--reporter",
                "append-only",
                "--config.enable-modules-dir=false",
                "--config.node-linker=isolated",
                "--config.modules-dir=../../store/tmp/stage-1/modules",
                "--config.virtual-store-dir=../store/tmp/stage-1/modules/.pnpm",
                "--config.store-dir=/store/tmp/stage-1/pnpm-store",
                "-w",
                "-D",
                "--",
                "@scope/pkg@1.2.3"
            ]
        );
        // Every verb comes from `Verb::command`, and every verb whose pnpm
        // parser accepts `--ignore-scripts` carries it. `remove` is the one
        // exception: pnpm rejects the flag there ("Unknown option:
        // 'ignore-scripts'"), so `npm_config_ignore_scripts` in the delegate
        // environment is what stops its lifecycle scripts.
        for verb in [Verb::Add, Verb::Remove, Verb::Update] {
            let args = node_delegate_args(verb, &[], false, false, &scratch);
            assert_eq!(args[0], verb.command());
            // The modules-state redirection is on every verb: `remove` and
            // `update` reject `--modules-dir` as a flag but take `--config.`.
            assert!(args.contains(&"--config.enable-modules-dir=false".to_string()));
            // Without a forced linker a project `.npmrc` (`node-linker=hoisted`)
            // turns the delegate back into a real installer.
            assert!(args.contains(&"--config.node-linker=isolated".to_string()));
            assert!(args
                .iter()
                .any(|arg| arg.starts_with("--config.store-dir=")));
            assert!(args
                .iter()
                .any(|arg| arg.starts_with("--config.modules-dir=")));
            assert!(args
                .iter()
                .any(|arg| arg.starts_with("--config.virtual-store-dir=")));
            assert_eq!(
                args.contains(&"--ignore-scripts".to_string()),
                verb != Verb::Remove,
                "{verb:?} delegate argv: {args:?}"
            );
        }
        assert!(validate_delegate_specs(&["--prefix=/tmp".into()]).is_err());
    }

    /// Lexically resolve `base/relative` (`..` pops), the way pnpm's
    /// `path.join` does, to check where a relative setting lands.
    fn lexical_join(base: &Path, relative: &str) -> PathBuf {
        let mut out = base.to_path_buf();
        for component in Path::new(relative).components() {
            match component {
                std::path::Component::ParentDir => {
                    out.pop();
                }
                std::path::Component::Normal(name) => out.push(name),
                _ => {}
            }
        }
        out
    }

    /// pnpm joins `modules-dir` onto every importer's directory and
    /// `virtual-store-dir` onto the lock root. From the project pnpm runs in
    /// both land in tog's stage, and from any shallower importer the
    /// modules dir still escapes the project tree. A root-computed one lands
    /// back inside the project for a deeper importer; the linker flags, not
    /// this path, are what keep that harmless.
    #[test]
    fn pnpm_scratch_paths_resolve_where_pnpm_joins_them() {
        let temp = TempDir::named("pnpm-scratch");
        let root = temp.0.clone();
        let stage = root.join("store/tmp/stage-1");
        let lock_root = root.join("proj");
        let member = lock_root.join("packages/lib");
        fs::create_dir_all(&stage).unwrap();
        fs::create_dir_all(&member).unwrap();
        let stage_c = stage.canonicalize().unwrap();
        let lock_root_c = lock_root.canonicalize().unwrap();
        let member_c = member.canonicalize().unwrap();

        let scratch = pnpm_scratch(&stage, &member, &lock_root).unwrap();
        assert!(
            !scratch.modules_dir.starts_with('/'),
            "{}",
            scratch.modules_dir
        );
        assert!(
            !scratch.virtual_store_dir.starts_with('/'),
            "{}",
            scratch.virtual_store_dir
        );
        assert_eq!(
            lexical_join(&member_c, &scratch.modules_dir),
            stage_c.join("modules")
        );
        assert_eq!(
            lexical_join(&lock_root_c, &scratch.virtual_store_dir),
            stage_c.join("modules/.pnpm")
        );
        // The root importer joins the same modules-dir onto its own path.
        let from_root = lexical_join(&lock_root_c, &scratch.modules_dir);
        assert!(
            !from_root.starts_with(&lock_root_c),
            "root importer's modules dir {} is inside the project",
            from_root.display()
        );

        let scratch = pnpm_scratch(&stage, &lock_root, &lock_root).unwrap();
        assert_eq!(
            lexical_join(&lock_root_c, &scratch.modules_dir),
            stage_c.join("modules")
        );
        // A root-computed modules-dir lands INSIDE the project for a deeper
        // importer. This is a property of `path.join` and one relative path,
        // not something to be fixed by computing it differently; it is
        // asserted here so nobody reads the previous claim ("escapes from
        // every importer") back into the code. Safety comes from the linker
        // flags in `node_delegate_args`, and
        // `deps_e2e::pnpm_edits_leave_an_installed_project_untouched` is what
        // proves it end to end.
        let from_member = lexical_join(&member_c, &scratch.modules_dir);
        assert!(
            from_member.starts_with(&lock_root_c),
            "expected the documented in-project landing, got {}",
            from_member.display()
        );
        assert_eq!(
            relative_path(Path::new("/a/b/c"), Path::new("/a/x/y")),
            PathBuf::from("../../x/y")
        );
        assert_eq!(
            relative_path(Path::new("/a"), Path::new("/a/x")),
            PathBuf::from("x")
        );
    }

    fn selected(project: &Path) -> (String, PathBuf) {
        match node_lock_for(project).unwrap() {
            NodeLock::Own { name, root } => (name, root),
            NodeLock::PnpmWorkspaceMember { root } => ("pnpm-lock.yaml".to_string(), root),
            NodeLock::UnlistedUnderPnpmWorkspace { workspace_root } => panic!(
                "expected a lock selection, got a refusal under the pnpm workspace {}",
                workspace_root.display()
            ),
        }
    }

    #[test]
    fn a_backslash_in_a_directory_name_takes_pnpms_own_slash_importer_key() {
        let scratch = TempDir::named("pnpm-backslash");
        let root = scratch.0.clone();
        fs::create_dir_all(root.join("packages").join("a\\b")).unwrap();
        fs::write(
            root.join("pnpm-lock.yaml"),
            "lockfileVersion: '9.0'\n\nimporters:\n\n  .: {}\n\n  packages/a/b: {}\n",
        )
        .unwrap();
        let member = root.join("packages").join("a\\b");
        assert!(
            matches!(
                pnpm_membership(&root, &member).unwrap(),
                PnpmMembership::Listed
            ),
            "pnpm 9.12.3 writes the importer key packages/a/b for the on-disk \
             directory packages/a\\b, so tog must normalise the same way"
        );
    }

    #[test]
    fn a_project_the_workspace_lock_does_not_list_refuses_instead_of_selecting_npm() {
        let scratch = TempDir::named("pnpm-unlisted");
        let root = scratch.0.clone();
        fs::create_dir_all(root.join("packages/listed")).unwrap();
        fs::create_dir_all(root.join("packages/added-since-install")).unwrap();
        fs::write(
            root.join("pnpm-lock.yaml"),
            "lockfileVersion: '9.0'\n\nimporters:\n\n  .: {}\n\n  packages/listed: {}\n",
        )
        .unwrap();
        fs::write(
            root.join("pnpm-workspace.yaml"),
            "packages:\n  - packages/*\n",
        )
        .unwrap();

        assert_eq!(
            selected(&root.join("packages/listed")),
            ("pnpm-lock.yaml".to_string(), root.clone())
        );

        let unlisted = node_lock_for(&root.join("packages/added-since-install")).unwrap();
        assert!(
            matches!(
                unlisted,
                NodeLock::UnlistedUnderPnpmWorkspace { ref workspace_root } if workspace_root == &root
            ),
            "a member added since the last pnpm install must be reported, not \
             silently handed to npm"
        );
    }

    #[test]
    fn a_settings_only_pnpm_workspace_yaml_does_not_make_a_single_package_repo_a_workspace() {
        let scratch = TempDir::named("pnpm-settings-only");
        let root = scratch.0.clone();
        fs::create_dir_all(root.join("examples/demo")).unwrap();
        fs::write(
            root.join("pnpm-lock.yaml"),
            "lockfileVersion: '9.0'\n\nsettings:\n\n  autoInstallPeers: true\n\nimporters:\n\n  .: {}\n",
        )
        .unwrap();
        fs::write(
            root.join("pnpm-workspace.yaml"),
            "onlyBuiltDependencies:\n  - esbuild\n",
        )
        .unwrap();

        let nested = root.join("examples/demo");
        assert_eq!(
            selected(&nested),
            ("package-lock.json".to_string(), nested.clone()),
            "since pnpm 10 pnpm-workspace.yaml is also the project settings \
             file, so its presence alone must not make an ordinary \
             single-package repository a workspace that swallows every \
             subdirectory"
        );
        assert!(
            matches!(
                pnpm_membership(&root, &nested).unwrap(),
                PnpmMembership::NotAWorkspace
            ),
            "a lock whose only importer is the root itself describes a \
             single-package repository"
        );
    }

    #[test]
    fn node_lock_selection_prefers_own_lock_and_reads_workspace_membership_from_the_lock() {
        let scratch = TempDir::named("node-lock-selection");
        let root = scratch.0.clone();
        fs::create_dir_all(root.join("packages/lib")).unwrap();
        fs::create_dir_all(root.join("packages/private")).unwrap();
        fs::write(
            root.join("pnpm-lock.yaml"),
            "lockfileVersion: '9.0'\n\nimporters:\n\n  .: {}\n\n  packages/lib: {}\n",
        )
        .unwrap();
        fs::write(
            root.join("pnpm-workspace.yaml"),
            "packages:\n  - '!packages/private'\n  - packages/*\n",
        )
        .unwrap();
        let member = root.join("packages/lib");
        assert_eq!(
            selected(&member),
            ("pnpm-lock.yaml".to_string(), root.clone())
        );

        let independent = root.join("packages/private");
        let excluded = node_lock_for(&independent).unwrap();
        assert!(
            matches!(
                excluded,
                NodeLock::UnlistedUnderPnpmWorkspace { ref workspace_root } if workspace_root == &root
            ),
            "tog does not reimplement pnpm's exclusion globs, so a project \
             the lock does not list is ambiguous and must refuse rather than \
             guess npm"
        );

        fs::create_dir_all(independent.join(".tog")).unwrap();
        assert_eq!(
            selected(&independent),
            ("package-lock.json".to_string(), independent.clone()),
            "a .tog directory is how a project inside a workspace tree \
             declares itself its own root"
        );
        fs::remove_dir_all(independent.join(".tog")).unwrap();

        fs::write(independent.join("package-lock.json"), "{}\n").unwrap();
        assert_eq!(
            selected(&independent),
            ("package-lock.json".to_string(), independent.clone())
        );

        fs::write(member.join("package-lock.json"), "{}\n").unwrap();
        fs::write(root.join("package-lock.json"), "{}\n").unwrap();
        assert_eq!(selected(&member), ("package-lock.json".to_string(), member));

        let boundary = root.join("packages/boundary");
        fs::create_dir_all(boundary.join(".tog")).unwrap();
        assert_eq!(
            selected(&boundary),
            ("package-lock.json".to_string(), boundary)
        );
    }

    #[test]
    fn ancestor_non_pnpm_locks_and_no_lock_projects_are_boundaries() {
        let scratch = TempDir::named("node-lock-boundaries");
        let root = scratch.0.clone();
        let nested = root.join("tools/nested");
        fs::create_dir_all(&nested).unwrap();
        fs::write(nested.join("package.json"), "{}\n").unwrap();

        fs::write(root.join("package-lock.json"), "{}\n").unwrap();
        assert_eq!(
            selected(&nested),
            ("package-lock.json".to_string(), nested.clone())
        );
        fs::remove_file(root.join("package-lock.json")).unwrap();
        fs::write(root.join("yarn.lock"), "# yarn lockfile v1\n").unwrap();
        assert_eq!(
            selected(&nested),
            ("package-lock.json".to_string(), nested.clone())
        );
        fs::remove_file(root.join("yarn.lock")).unwrap();
        assert_eq!(selected(&nested), ("package-lock.json".to_string(), nested));
    }

    #[test]
    fn unmatched_pnpm_workspace_is_a_boundary_to_an_outer_workspace() {
        let scratch = TempDir::named("nested-pnpm-boundary");
        let root = scratch.0.clone();
        let inner = root.join("inner");
        let member = inner.join("member");
        fs::create_dir_all(&member).unwrap();
        fs::write(root.join("pnpm-lock.yaml"), "lockfileVersion: '9.0'\n").unwrap();
        fs::write(
            root.join("pnpm-workspace.yaml"),
            "packages:\n  - inner/**\n",
        )
        .unwrap();
        fs::write(inner.join("pnpm-lock.yaml"), "lockfileVersion: '9.0'\n").unwrap();
        fs::write(
            inner.join("pnpm-workspace.yaml"),
            "packages:\n  - '!member'\n",
        )
        .unwrap();
        fs::write(member.join("package.json"), "{}\n").unwrap();

        assert_eq!(selected(&member), ("package-lock.json".to_string(), member));
    }

    #[test]
    fn mixed_sync_roots_are_rejected_before_delegation() {
        let scratch = TempDir::named("mixed-sync-roots");
        let root = scratch.0.clone();
        fs::create_dir_all(root.join("packages/member")).unwrap();
        fs::write(
            root.join("pnpm-lock.yaml"),
            "lockfileVersion: '9.0'\n\nimporters:\n\n  .: {}\n\n  packages/member: {}\n",
        )
        .unwrap();
        fs::write(
            root.join("pnpm-workspace.yaml"),
            "packages:\n  - packages/*\n",
        )
        .unwrap();
        let member = root.join("packages/member");
        let groups = vec![(Eco::Python, Vec::new()), (Eco::Node, Vec::new())];
        let error = reject_mixed_sync_roots(Verb::Add, &member, &groups).unwrap_err();
        let message = error.to_string();
        assert!(message.contains(&member.display().to_string()), "{message}");
        assert!(message.contains(&root.display().to_string()), "{message}");
        assert!(message.contains("run the two adds separately"), "{message}");
    }

    #[test]
    fn yarn_berry_uses_conversion_refusal_without_delegation() {
        let scratch = TempDir::named("yarn-berry-detection");
        let root = scratch.0.clone();
        fs::write(
            root.join("package.json"),
            "{\"packageManager\":\"yarn@1.22.22\"}\n",
        )
        .unwrap();
        assert!(!is_yarn_berry(&root));
        fs::write(root.join(".yarnrc.yml"), "nodeLinker: node-modules\n").unwrap();
        assert!(is_yarn_berry(&root));
        fs::remove_file(root.join(".yarnrc.yml")).unwrap();
        fs::write(
            root.join("package.json"),
            "{\"packageManager\":\"yarn@2.4.3\"}\n",
        )
        .unwrap();
        assert!(is_yarn_berry(&root));
        let error = yarn_refusal(&root, Verb::Add, &["react".into()], false);
        assert!(
            error.to_string().contains(
                "convert with 'npm install --package-lock-only' or 'pnpm install --lockfile-only'"
            ),
            "{error}"
        );
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
        // Rung 3: the only ecosystem present decides, no lookup.
        assert_eq!(
            choose(&spec("react"), &[Eco::Node], &mut lookup, &mut ask).unwrap(),
            Eco::Node
        );
        assert!(lookups.borrow().is_empty());
        // Rung 4: registries decide when exactly one knows the name.
        assert_eq!(
            choose(&spec("react"), &both, &mut lookup, &mut ask).unwrap(),
            Eco::Node
        );
        assert_eq!(lookups.borrow().len(), 2);
        // Rung 4, nobody knows: error names the explicit spellings.
        let error = choose(&spec("nothing"), &both, &mut lookup, &mut ask).unwrap_err();
        assert!(
            error.to_string().contains("py:nothing / npm:nothing"),
            "{error}"
        );
        assert!(asked.borrow().is_empty());
        // Rung 5: both know it → ask, with the versions.
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

        let scratch = TempDir::named("deps");
        let temp = scratch.0.clone();
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
    }

    #[test]
    fn requirement_edits_are_logical_lossless_and_ambiguous_edits_fail() {
        let scratch = TempDir::named("deps-logical");
        let temp = scratch.0.clone();
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
    }

    #[cfg(unix)]
    #[test]
    fn requirement_edit_does_not_follow_predictable_temp_symlink() {
        use std::os::unix::fs::symlink;
        use std::os::unix::fs::PermissionsExt;

        let scratch = TempDir::named("deps-atomic");
        let temp = scratch.0.clone();
        let file = temp.join("requirements.txt");
        let target = temp.join("outside");
        let old_temp = file.with_extension(format!("tog-edit.{}", std::process::id()));
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
    }

    #[test]
    fn python_shapes_follow_the_sync_order() {
        let scratch = TempDir::named("shape");
        let temp = scratch.0.clone();
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

    /// The scope `run` opens for an edit: exceptions recorded in it, and
    /// in an ecosystem scope nested under it, are gone once it is
    /// discarded, so the sync after the edit starts from nothing. This
    /// covers the scope, not `run`'s own call to `discard`: `run` edits
    /// through a real package manager, which needs the network.
    #[test]
    fn discarding_the_edit_scope_leaves_no_exception_pending() {
        let _supervision = crate::kernel::supervise::SUPERVISION_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let _store_lock = crate::kernel::store::STORE_ENV_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let _attribution = policy::attribution_test_lock();
        let mut edit = edit_attribution().unwrap();
        policy::record_with(
            &policy::Policy::default(),
            policy::SKIPPED_OPTIONAL,
            "dependency-edit fixture",
            "optional dependency was not requested",
        )
        .unwrap();
        let mut node = edit.nested("node").unwrap();
        policy::record_with(
            &policy::Policy::default(),
            policy::GIT_DEPENDENCY,
            "node fixture",
            "nested Node realization",
        )
        .unwrap();
        let node_exceptions = node.claim("node").unwrap();
        assert_eq!(node_exceptions.len(), 1);
        node.mark_published().unwrap();
        node.finish(true).unwrap();
        edit.discard();
        assert!(
            policy::pending().is_empty(),
            "dependency edit left an exception queued: {:?}",
            policy::pending()
        );
        let next = policy::Attribution::open("python").unwrap();
        drop(next);
    }
}

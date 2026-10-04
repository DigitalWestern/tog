//! `add`, `remove`, `update`.
//!
//! Each ecosystem's edit is its tailor's (`Tailor::edit_manifest`): the
//! tailor delegates it to its pinned tool through the resolution door, or
//! refuses with the exact line and file. What stays here is
//! ecosystem-neutral: validating the specs, choosing the ecosystem, the
//! report lines, and the sync after the edit.
//!
//! Choosing the ecosystem is an evidence ladder: an explicit prefix, the
//! name's shape, the nearest manifest, the registries, then the human.
//! Never a coin flip.

use std::fmt;
use std::io::{self, BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};

use crate::commands::shared::{
    edit_tailors, project_dir, selected_toolchain, CachedTool, DepSpec, EditHost, ManifestEdit,
    PackageRegistry, Tailor,
};
use crate::commands::sync;
use crate::commands::x as xrun;
use crate::kernel::context::Context;
use crate::kernel::platform::Platform;
use crate::kernel::policy;
use crate::kernel::resolve::{DoorKind, ResolutionDoor};
use crate::kernel::store::Store;
use crate::kernel::toolchain::Selected;
use crate::kernel::ui;

/// Which edit: the tailors' own `EditVerb`.
pub(crate) use crate::commands::shared::EditVerb as Verb;

/// An ecosystem `tog add` can choose: a tailor with a public package
/// registry (`Tailor::package_registry`).
#[derive(Clone, Copy)]
pub struct Eco {
    tailor: &'static dyn Tailor,
    registry: PackageRegistry,
}

impl PartialEq for Eco {
    fn eq(&self, other: &Self) -> bool {
        self.name() == other.name()
    }
}

impl Eq for Eco {}

impl fmt::Debug for Eco {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.name())
    }
}

impl Eco {
    /// Every ecosystem `tog add` can choose, in registry order.
    pub fn all() -> Vec<Eco> {
        edit_tailors()
            .into_iter()
            .map(|(tailor, registry)| Eco { tailor, registry })
            .collect()
    }

    pub fn name(self) -> &'static str {
        self.tailor.id()
    }

    /// The explicit spelling: `npm:react`, `py:requests`, ...
    pub fn prefix(self) -> &'static str {
        self.registry.prefix
    }

    pub fn registry(self) -> &'static str {
        self.registry.name
    }

    fn from_name(name: &str) -> Option<Eco> {
        Eco::all().into_iter().find(|eco| eco.name() == name)
    }

    fn from_prefix(prefix: &str) -> Option<Eco> {
        Eco::all().into_iter().find(|eco| eco.prefix() == prefix)
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

/// Rung 2: names whose shape fixes the ecosystem
/// (`Tailor::claims_package_name`).
pub fn shape(name: &str) -> Option<Eco> {
    Eco::all()
        .into_iter()
        .find(|eco| eco.tailor.claims_package_name(name))
}

/// The project at or above `cwd` (`shared::project_for`), which must hold
/// a project input.
pub fn nearest_project(cwd: &Path) -> io::Result<(PathBuf, Vec<Eco>)> {
    if let Some(location) = crate::commands::shared::project_for(cwd)? {
        let present: Vec<Eco> = location
            .detected
            .into_iter()
            .filter_map(Eco::from_name)
            .collect();
        if !present.is_empty() {
            return Ok((location.root, present));
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!(
            "no project from {} upward (looked for {})",
            cwd.display(),
            crate::commands::shared::input_files()
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

/// Rung 4: does the registry know this name? `Some(latest version)`
/// (`Tailor::registry_exists`).
pub fn registry_lookup(eco: Eco, name: &str) -> io::Result<Option<String>> {
    eco.tailor.registry_exists(name)
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
/// hand each group to its tailor.
pub fn edit(
    ctx: &Context,
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
    let activity = &ctx.activity;
    // Every delegated tool below runs under the command's own lease.
    store.require_activity(activity, "dependency edit")?;
    let host = Host {
        platform: ctx.platform,
    };
    let mut door =
        ResolutionDoor::open(&store, activity, ctx.platform, DoorKind::Edit, attribution)?;
    let mut lines = Vec::new();
    let mut outcome_project = project.clone();
    for (eco, specs) in groups {
        let names: Vec<String> = specs.iter().map(|spec| spec.name.clone()).collect();
        let texts: Vec<String> = specs.iter().map(|spec| spec.text.clone()).collect();
        validate_delegate_specs(&texts)?;
        let specs: Vec<DepSpec> = specs
            .into_iter()
            .map(|spec| DepSpec {
                name: spec.name,
                text: spec.text,
            })
            .collect();
        let outcome = eco.tailor.edit_manifest(
            ctx,
            &ManifestEdit {
                verb: request.verb,
                project: &project,
                specs: &specs,
                dev: request.dev,
                host: &host,
            },
            &mut door,
        )?;
        outcome_project = outcome.sync_root;
        let what = if names.is_empty() {
            "everything".to_string()
        } else {
            names.join(", ")
        };
        lines.push(format!(
            "{}: {} {what}",
            outcome.files.join(", "),
            request.verb.past()
        ));
    }
    Ok(Outcome {
        project: outcome_project,
        lines,
    })
}

/// What an edit borrows from this command: toolchain selection outside a
/// sync, and the `tog x` cache a pinned package manager lives in.
struct Host {
    platform: Platform,
}

impl EditHost for Host {
    fn toolchain(&self, dir: &Path, ecosystem: &str) -> io::Result<Selected> {
        selected_toolchain(self.platform, dir, ecosystem)
    }

    fn cached_tool(
        &self,
        ecosystem: &str,
        project: &Path,
        package: &str,
        version: &str,
        door: &mut ResolutionDoor<'_>,
    ) -> io::Result<CachedTool> {
        xrun::realize_cached_tool(project, ecosystem, package, version, door)
    }
}

fn reject_mixed_sync_roots(
    verb: Verb,
    project: &Path,
    groups: &[(Eco, Vec<Spec>)],
) -> io::Result<()> {
    let mut roots = Vec::new();
    for (eco, _) in groups {
        let root = eco.tailor.edit_root(project)?;
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

/// `add` / `remove` / `update`: delegate the edit, report it, then the
/// ordinary sync in the project the edit landed in.
pub fn run(ctx: &Context, request: Request, no_sync: bool) -> io::Result<()> {
    let cwd = project_dir();
    // Dependency edits ensure pinned tools before the ordinary sync. Load
    // the policy chain first: a cached toolchain object read before it
    // would fix the process policy without the policy files, and their
    // deny entries would not apply to the edit or the sync after it.
    policy::init(&cwd)?;
    // An interrupted resolution publication is undone before the edit
    // reads the manifest or the lock it left half-written.
    if crate::kernel::resolve::transaction::has_pending_journal(&cwd) {
        crate::kernel::resolve::transaction::recover_project(&ctx.store, &ctx.activity, &cwd)?;
    }
    let mut edit_attribution = edit_attribution()?;
    let outcome = edit(ctx, &cwd, request, &mut edit_attribution)?;
    for line in &outcome.lines {
        ui::note(line);
    }
    if no_sync {
        ui::note("--no-sync: review the change, then run 'tog'");
        edit_attribution.discard();
        return Ok(());
    }
    if outcome.project != cwd {
        ui::trace(&format!("syncing in {}", outcome.project.display()));
    }
    // The edit owns its exceptions. Sync must open a fresh ecosystem scope.
    edit_attribution.discard();
    sync::run_in(ctx, &outcome.project, false, false)
}

/// Open the dependency edit's attribution scope before the edit can record.
///
/// `edit` records exceptions of its own, outside any ecosystem's closure: on
/// a warm store every `ensure_*_for` replays cached-object exceptions
/// through `policy::check_cached_with_activity`. Those belong to the edit, not to whichever
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
    use std::fs;

    fn spec(text: &str) -> Spec {
        parse_spec(text)
    }

    fn ecosystem(name: &str) -> Eco {
        Eco::from_name(name).unwrap()
    }

    #[test]
    fn specs_split_prefix_name_and_constraint() {
        assert_eq!(
            spec("npm:react@18"),
            Spec {
                text: "react@18".into(),
                name: "react".into(),
                eco: Some(ecosystem("node"))
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
        assert_eq!(spec("nuget:Newtonsoft.Json").eco, Some(ecosystem("dotnet")));
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
        assert!(validate_delegate_specs(&["--prefix=/tmp".into()]).is_err());
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
        let groups = vec![
            (ecosystem("python"), Vec::new()),
            (ecosystem("node"), Vec::new()),
        ];
        let error = reject_mixed_sync_roots(Verb::Add, &member, &groups).unwrap_err();
        let message = error.to_string();
        assert!(message.contains(&member.display().to_string()), "{message}");
        assert!(message.contains(&root.display().to_string()), "{message}");
        assert!(message.contains("run the two adds separately"), "{message}");
    }

    #[test]
    fn shapes_are_structural() {
        assert_eq!(shape("@types/node"), Some(ecosystem("node")));
        assert_eq!(shape("github.com/spf13/cobra"), Some(ecosystem("go")));
        assert_eq!(shape("Newtonsoft.Json"), Some(ecosystem("dotnet")));
        assert_eq!(
            shape("Microsoft.Extensions.Logging"),
            Some(ecosystem("dotnet"))
        );
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
            Ok(match (eco.name(), name) {
                ("python", "requests") => Some("2.32.5".into()),
                ("node", "requests") => Some("0.3.0".into()),
                ("node", "react") => Some("19.0.0".into()),
                _ => None,
            })
        };
        let mut ask = |name: &str, known: &[(Eco, String)]| -> io::Result<Eco> {
            asked.borrow_mut().push((name.to_string(), known.to_vec()));
            Ok(known[0].0)
        };
        let both = [ecosystem("python"), ecosystem("node")];

        // Rung 1: prefix, no lookup.
        assert_eq!(
            choose(&spec("npm:react"), &both, &mut lookup, &mut ask).unwrap(),
            ecosystem("node")
        );
        // Rung 2: shape, no lookup.
        assert_eq!(
            choose(&spec("@types/node"), &both, &mut lookup, &mut ask).unwrap(),
            ecosystem("node")
        );
        // Rung 2 against a project without that ecosystem is an error.
        let error = choose(&spec("github.com/x/y"), &both, &mut lookup, &mut ask).unwrap_err();
        assert!(error.to_string().contains("no go manifest"), "{error}");
        // Rung 3: the only ecosystem present decides, no lookup.
        assert_eq!(
            choose(&spec("react"), &[ecosystem("node")], &mut lookup, &mut ask).unwrap(),
            ecosystem("node")
        );
        assert!(lookups.borrow().is_empty());
        // Rung 4: registries decide when exactly one knows the name.
        assert_eq!(
            choose(&spec("react"), &both, &mut lookup, &mut ask).unwrap(),
            ecosystem("node")
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
            ecosystem("python")
        );
        let asked = asked.borrow();
        assert_eq!(asked.len(), 1);
        assert_eq!(asked[0].1[0], (ecosystem("python"), "2.32.5".to_string()));
        assert_eq!(asked[0].1[1], (ecosystem("node"), "0.3.0".to_string()));
    }

    /// The scope `run` opens for an edit: exceptions recorded in it, and
    /// in an ecosystem scope nested under it, are gone once it is
    /// discarded, so the sync after the edit starts from nothing. This
    /// covers the scope, not `run`'s own call to `discard`: `run` edits
    /// through a real package manager, which needs the network.
    #[test]
    fn discarding_the_edit_scope_leaves_no_exception_pending() {
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

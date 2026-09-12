//! Turning argv into a `Parsed` invocation, one command at a time.

use std::path::PathBuf;

use super::spec::{
    canonical_name, help, spec, usage, COMMANDS, LS_WORDS, SHELL_WORDS, SYNC_ALIASES,
};
use super::{Command, GcArgs, Invocation, Options, Parsed, Shell, Spec, UsageError, VERSION};

const VERSION_WORDS: [&str; 3] = ["-V", "--version", "version"];
const HELP_WORDS: [&str; 3] = ["-h", "--help", "help"];

fn version_text() -> String {
    format!("blanket {VERSION}\n")
}

pub fn parse(args: &[String]) -> Result<Parsed, UsageError> {
    let mut options = Options::default();
    let mut index = 0;
    while let Some(arg) = args.get(index).map(String::as_str) {
        if HELP_WORDS.contains(&arg) {
            return help_topic(args.get(index + 1).map(String::as_str)).map(Parsed::Print);
        }
        if VERSION_WORDS.contains(&arg) {
            return Ok(Parsed::Print(version_text()));
        }
        match arg {
            "-C" | "--directory" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| UsageError::new(format!("{arg} needs a directory"), None))?;
                options.directory = Some(PathBuf::from(value));
                index += 2;
            }
            _ if arg.starts_with("--directory=") => {
                options.directory = Some(non_empty(
                    &arg["--directory=".len()..],
                    "--directory",
                    None,
                )?);
                index += 1;
            }
            _ if arg.starts_with("-C") => {
                options.directory = Some(PathBuf::from(&arg[2..]));
                index += 1;
            }
            "-q" | "--quiet" => {
                options.quiet = true;
                index += 1;
            }
            "-v" | "--verbose" => {
                options.verbose = true;
                index += 1;
            }
            "--no-color" => {
                options.no_color = true;
                index += 1;
            }
            _ if arg.starts_with('-') => {
                let known = [
                    "--directory",
                    "--quiet",
                    "--verbose",
                    "--no-color",
                    "--help",
                    "--version",
                ];
                return Err(UsageError::new(
                    with_suggestion(
                        format!("unknown option '{arg}'"),
                        flag_name(arg),
                        known.iter().copied(),
                    ),
                    None,
                ));
            }
            _ => break,
        }
    }
    let Some(word) = args.get(index).map(String::as_str) else {
        return Ok(Parsed::Implicit(options));
    };
    let rest = &args[index + 1..];
    let name = canonical_name(word);
    let command = match name {
        "sync" => parse_sync(rest)?,
        "fmt" => parse_fmt(rest)?,
        "plan" => parse_plan(rest)?,
        "build" => parse_passthrough(rest, "build")?,
        "run" => parse_passthrough(rest, "run")?,
        "sbom" => parse_sbom(rest)?,
        "add" | "remove" | "update" => parse_deps(rest, name)?,
        "x" => parse_x(rest)?,
        "status" => parse_json_only(rest, "status")?.map(|json| Command::Status { json }),
        "audit" => parse_audit(rest)?,
        "ls" => parse_ls(rest)?,
        "doctor" => parse_json_only(rest, "doctor")?.map(|json| Command::Doctor { json }),
        "gc" => parse_gc(rest)?,
        "store" => parse_store(rest)?,
        "completions" => parse_completions(rest)?,
        other => {
            return Ok(Parsed::Script {
                options,
                name: other.to_string(),
                args: rest.to_vec(),
                message: with_suggestion(
                    format!("unknown command '{other}'"),
                    other,
                    COMMANDS
                        .iter()
                        .map(|spec| spec.name)
                        .chain(["help", "version"]),
                ),
            });
        }
    };
    let command = match command {
        Some(command) => command,
        None => return Ok(Parsed::Print(help(spec(name).expect("known command")))),
    };
    Ok(Parsed::Run(Invocation { options, command }))
}

fn help_topic(topic: Option<&str>) -> Result<String, UsageError> {
    match topic {
        None => Ok(usage()),
        Some(name) if HELP_WORDS.contains(&name) => Ok(usage()),
        Some(name) if VERSION_WORDS.contains(&name) => Ok(version_text()),
        Some(name) => spec(name).map(help).ok_or_else(|| {
            UsageError::new(
                with_suggestion(
                    format!("no help for '{name}': not a blanket command"),
                    name,
                    COMMANDS.iter().map(|spec| spec.name),
                ),
                None,
            )
        }),
    }
}

/// `Ok(None)` means the command's help was requested.
fn parse_sync(args: &[String]) -> Result<Option<Command>, UsageError> {
    let mut fresh = false;
    let mut strict = false;
    for arg in args {
        match arg.as_str() {
            "--fresh" => fresh = true,
            "--strict" => strict = true,
            "-h" | "--help" => return Ok(None),
            other => return Err(reject("sync", other)),
        }
    }
    Ok(Some(Command::Sync { fresh, strict }))
}

fn parse_fmt(args: &[String]) -> Result<Option<Command>, UsageError> {
    let mut check = false;
    let mut ecosystem = None;
    let mut passthrough = false;
    let mut tool_args = Vec::new();
    let mut index = 0;
    while let Some(arg) = args.get(index) {
        if index == 0 && matches!(arg.as_str(), "-h" | "--help") {
            return Ok(None);
        }
        if passthrough {
            tool_args.push(arg.clone());
            index += 1;
            continue;
        }
        match arg.as_str() {
            "--" => passthrough = true,
            "--check" => check = true,
            "--eco" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| UsageError::new("fmt: --eco needs an ecosystem", Some("fmt")))?;
                if value.is_empty() || value.starts_with('-') {
                    return Err(UsageError::new(
                        "fmt: --eco needs an ecosystem",
                        Some("fmt"),
                    ));
                }
                ecosystem = Some(value.clone());
                index += 1;
            }
            value if value.starts_with("--eco=") => {
                // Same rule as the separate-word form: a mistyped flag
                // (`--eco=--check`) is a usage error, not an ecosystem name.
                let value = &value["--eco=".len()..];
                if value.is_empty() || value.starts_with('-') {
                    return Err(UsageError::new(
                        "fmt: --eco needs an ecosystem",
                        Some("fmt"),
                    ));
                }
                ecosystem = Some(value.to_string());
            }
            value
                if value.starts_with("--")
                    && suggest(value, ["--check", "--eco"].into_iter()).is_some() =>
            {
                return Err(reject("fmt", value));
            }
            value => {
                passthrough = true;
                tool_args.push(value.to_string());
            }
        }
        index += 1;
    }
    Ok(Some(Command::Fmt {
        check,
        ecosystem,
        args: tool_args,
    }))
}

fn parse_plan(args: &[String]) -> Result<Option<Command>, UsageError> {
    match args.first().map(String::as_str) {
        None => Ok(Some(Command::Plan)),
        Some("-h" | "--help") => Ok(None),
        Some(other) => Err(reject("plan", other)),
    }
}

/// Commands whose only option is `--json`. `Ok(Some(json))`.
fn parse_json_only(args: &[String], name: &'static str) -> Result<Option<bool>, UsageError> {
    let mut json = false;
    for arg in args {
        match arg.as_str() {
            "--json" => json = true,
            "-h" | "--help" => return Ok(None),
            other => return Err(reject(name, other)),
        }
    }
    Ok(Some(json))
}

fn parse_audit(args: &[String]) -> Result<Option<Command>, UsageError> {
    let mut policy = None;
    let mut json = false;
    let mut index = 0;
    while let Some(arg) = args.get(index).map(String::as_str) {
        match arg {
            "--json" => json = true,
            "-h" | "--help" => return Ok(None),
            // A mistyped flag (`--policy --json`) is a usage error, not a
            // file name; the same rule every value-taking flag here applies.
            "--policy" => {
                let value = args
                    .get(index + 1)
                    .filter(|value| !value.starts_with('-'))
                    .ok_or_else(|| UsageError::new("--policy needs a file path", Some("audit")))?;
                policy = Some(non_empty(value, "--policy", Some("audit"))?);
                index += 1;
            }
            _ if arg.starts_with("--policy=") => {
                let value = &arg["--policy=".len()..];
                if value.starts_with('-') {
                    return Err(UsageError::new("--policy needs a file path", Some("audit")));
                }
                policy = Some(non_empty(value, "--policy", Some("audit"))?);
            }
            other => return Err(reject("audit", other)),
        }
        index += 1;
    }
    Ok(Some(Command::Audit { policy, json }))
}

fn parse_ls(args: &[String]) -> Result<Option<Command>, UsageError> {
    let mut json = false;
    let mut ecosystem = None;
    for arg in args {
        match arg.as_str() {
            "--json" => json = true,
            "-h" | "--help" => return Ok(None),
            other if other.starts_with('-') => return Err(reject("ls", other)),
            other => {
                if ecosystem.is_some() {
                    return Err(UsageError::new(
                        format!("ls: unexpected argument '{other}' (one ecosystem at most)"),
                        Some("ls"),
                    ));
                }
                if !LS_WORDS.contains(&other) {
                    return Err(UsageError::new(
                        with_suggestion(
                            format!(
                                "ls: unknown ecosystem '{other}' (one of: {})",
                                LS_WORDS.join(", ")
                            ),
                            other,
                            LS_WORDS.iter().copied(),
                        ),
                        Some("ls"),
                    ));
                }
                ecosystem = Some(other.to_string());
            }
        }
    }
    Ok(Some(Command::Ls { ecosystem, json }))
}

/// `run` and `build` own only a leading help flag; `--` forces pass-through
/// of a program argument that happens to be `-h`.
fn parse_passthrough(args: &[String], name: &'static str) -> Result<Option<Command>, UsageError> {
    let args = match args.first().map(String::as_str) {
        Some("-h" | "--help") => return Ok(None),
        Some("--") => &args[1..],
        _ => args,
    };
    if name == "run" && args.is_empty() {
        return Err(UsageError::new("run: no command given", Some("run")));
    }
    let args = args.to_vec();
    Ok(Some(match name {
        "run" => Command::Run { command: args },
        _ => Command::Build { args },
    }))
}

fn parse_deps(args: &[String], name: &str) -> Result<Option<Command>, UsageError> {
    let name: &'static str = match name {
        "add" => "add",
        "remove" => "remove",
        _ => "update",
    };
    let mut dev = false;
    let mut no_sync = false;
    let mut positional = Vec::new();
    let mut passthrough = false;
    for arg in args {
        if passthrough {
            validate_dependency_arg(name, arg)?;
            positional.push(arg.clone());
            continue;
        }
        match arg.as_str() {
            "--" => passthrough = true,
            "-h" | "--help" => return Ok(None),
            "--no-sync" => no_sync = true,
            "--dev" | "-D" if matches!(name, "add" | "remove") => dev = true,
            other if other.starts_with('-') && other.len() > 1 => return Err(reject(name, other)),
            other => {
                validate_dependency_arg(name, other)?;
                positional.push(other.to_string());
            }
        }
    }
    match name {
        "add" if positional.is_empty() => Err(UsageError::new(
            "add: no package given (e.g. 'blanket add requests', 'blanket add npm:react@18')",
            Some("add"),
        )),
        "add" => Ok(Some(Command::Add {
            specs: positional,
            dev,
            no_sync,
        })),
        "remove" if positional.is_empty() => {
            Err(UsageError::new("remove: no package given", Some("remove")))
        }
        "remove" => Ok(Some(Command::Remove {
            names: positional,
            dev,
            no_sync,
        })),
        _ => Ok(Some(Command::Update {
            names: positional,
            no_sync,
        })),
    }
}

fn validate_dependency_arg(name: &'static str, arg: &str) -> Result<(), UsageError> {
    // Keep malformed argv at the grammar boundary. In particular, a newline
    // in a requirements spec must never reach a text append or a delegated
    // package-manager command, and an option-looking package must not become
    // an option to that tool after `--`.
    if arg.bytes().any(|byte| matches!(byte, b'\r' | b'\n' | 0)) {
        return Err(UsageError::new(
            format!("{name}: dependency spec contains CR, LF, or NUL"),
            Some(name),
        ));
    }
    crate::deps::validate_spec(arg)
        .map_err(|error| UsageError::new(format!("{name}: {error}"), Some(name)))
}

fn parse_x(args: &[String]) -> Result<Option<Command>, UsageError> {
    let mut ecosystem = None;
    let mut from = None;
    let mut clean = false;
    let mut index = 0;
    while let Some(arg) = args.get(index).map(String::as_str) {
        match arg {
            "-h" | "--help" => return Ok(None),
            "--clean" => clean = true,
            "--py" | "--python" => ecosystem = Some("python".to_string()),
            "--npm" | "--node" => ecosystem = Some("node".to_string()),
            "--from" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| UsageError::new("--from needs a package name", Some("x")))?;
                validate_x_package(value)?;
                from = Some(value.clone());
                index += 1;
            }
            _ if arg.starts_with("--from=") => {
                let value = non_empty(&arg["--from=".len()..], "--from", Some("x"))?
                    .to_string_lossy()
                    .into_owned();
                validate_x_package(&value)?;
                from = Some(value);
            }
            "--" => {
                index += 1;
                break;
            }
            _ if arg.starts_with('-') && arg.len() > 1 => return Err(reject("x", arg)),
            _ => break,
        }
        index += 1;
    }
    let Some(tool) = args.get(index) else {
        if clean {
            if from.is_some() {
                return Err(UsageError::new(
                    "x: --clean --from requires a tool name",
                    Some("x"),
                ));
            }
            return Ok(Some(Command::XClean {
                ecosystem,
                from,
                tool: None,
            }));
        }
        return Err(UsageError::new(
            "x: no tool given (e.g. 'blanket x ruff check .', 'blanket x npm:prettier --write .')",
            Some("x"),
        ));
    };
    let mut tool = tool.clone();
    if let Some(rest) = tool.strip_prefix("py:") {
        ecosystem = Some("python".to_string());
        tool = rest.to_string();
    } else if let Some(rest) = tool.strip_prefix("npm:") {
        ecosystem = Some("node".to_string());
        tool = rest.to_string();
    }
    if clean && args.get(index + 1).is_some() {
        return Err(UsageError::new(
            format!("x --clean: unexpected argument '{}'", args[index + 1]),
            Some("x"),
        ));
    }
    if tool.is_empty() {
        return Err(UsageError::new("x: empty tool name", Some("x")));
    }
    if from.is_some() {
        let (bin, _) = split_x_version(&tool);
        validate_x_bin(bin)?;
    } else {
        // Without --from the tool is also the package name, so npm scoped
        // names such as @scope/cli legitimately contain one slash.
        validate_x_text("tool", &tool, true)?;
    }
    validate_x_version_pair(from.as_deref(), &tool)?;
    if clean {
        return Ok(Some(Command::XClean {
            ecosystem,
            from,
            tool: Some(tool),
        }));
    }
    Ok(Some(Command::X {
        ecosystem,
        from,
        tool,
        args: args[index + 1..].to_vec(),
    }))
}

fn split_x_version(value: &str) -> (&str, Option<&str>) {
    match value.rfind('@') {
        Some(0) | None => (value, None),
        Some(index) => (&value[..index], Some(&value[index + 1..])),
    }
}

fn validate_x_version_pair(from: Option<&str>, tool: &str) -> Result<(), UsageError> {
    let (_, tool_version) = split_x_version(tool);
    let from_version = from.and_then(|value| split_x_version(value).1);
    for version in [from_version, tool_version].into_iter().flatten() {
        if version.is_empty()
            || version
                .bytes()
                .any(|byte| matches!(byte, b'\r' | b'\n' | 0))
            || version.chars().any(char::is_whitespace)
            || version.starts_with('-')
        {
            return Err(UsageError::new("x: invalid version", Some("x")));
        }
    }
    if let (Some(from), Some(tool)) = (from_version, tool_version) {
        if from != tool {
            return Err(UsageError::new(
                "x: --from package version conflicts with the tool version; specify only one or use the same version",
                Some("x"),
            ));
        }
    }
    Ok(())
}

fn validate_x_text(label: &str, value: &str, allow_slash: bool) -> Result<(), UsageError> {
    if value.is_empty()
        || value.bytes().any(|byte| matches!(byte, b'\r' | b'\n' | 0))
        || value.chars().any(char::is_whitespace)
        || value.starts_with('-')
        || (!allow_slash && (value.contains('/') || value.contains('\\')))
    {
        return Err(UsageError::new(
            format!("x: invalid {label} '{value}'"),
            Some("x"),
        ));
    }
    Ok(())
}

fn validate_x_package(value: &str) -> Result<(), UsageError> {
    // A scoped npm package contains one slash, but a filesystem path must
    // never be accepted as a package name. Version text is checked by xrun
    // after splitting package@version; these checks keep argv errors at exit 2.
    validate_x_text("package", value, true)?;
    if value.starts_with('/')
        || value.starts_with("./")
        || value.starts_with("../")
        || value.contains("/../")
        || value.ends_with("/..")
        || value.contains('\\')
    {
        return Err(UsageError::new(
            format!("x: invalid package '{value}'"),
            Some("x"),
        ));
    }
    Ok(())
}

fn validate_x_bin(value: &str) -> Result<(), UsageError> {
    if value.is_empty()
        || value == "."
        || value == ".."
        || !value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ".-_".contains(ch))
    {
        return Err(UsageError::new(
            "x: --from requires a single safe executable name",
            Some("x"),
        ));
    }
    Ok(())
}

fn parse_sbom(args: &[String]) -> Result<Option<Command>, UsageError> {
    let mut output = None;
    let mut index = 0;
    while let Some(arg) = args.get(index).map(String::as_str) {
        match arg {
            "-h" | "--help" => return Ok(None),
            "-o" | "--output" => {
                let value = args.get(index + 1).ok_or_else(|| {
                    UsageError::new(format!("{arg} needs a file path"), Some("sbom"))
                })?;
                output = Some(PathBuf::from(value));
                index += 1;
            }
            _ if arg.starts_with("--output=") => {
                output = Some(non_empty(
                    &arg["--output=".len()..],
                    "--output",
                    Some("sbom"),
                )?);
            }
            other => return Err(reject("sbom", other)),
        }
        index += 1;
    }
    Ok(Some(Command::Sbom { output }))
}

fn parse_gc(args: &[String]) -> Result<Option<Command>, UsageError> {
    let mut gc = GcArgs::default();
    let mut index = 0;
    while let Some(arg) = args.get(index).map(String::as_str) {
        match arg {
            "-h" | "--help" => return Ok(None),
            "--dry-run" => gc.dry_run = true,
            "--project" => gc.project = true,
            "--collect-legacy" => gc.collect_legacy = true,
            "--migrate-metadata" => gc.migrate_metadata = true,
            "--register" => {
                index += 1;
                let first = index;
                while index < args.len() && !args[index].starts_with("--") {
                    gc.register.push(PathBuf::from(&args[index]));
                    index += 1;
                }
                if first == index {
                    return Err(UsageError::new(
                        "--register needs at least one project directory",
                        Some("gc"),
                    ));
                }
                continue;
            }
            _ if arg.starts_with("--register=") => {
                gc.register.push(non_empty(
                    &arg["--register=".len()..],
                    "--register",
                    Some("gc"),
                )?);
            }
            "--forget" => {
                index += 1;
                let first = index;
                while index < args.len() && !args[index].starts_with("--") {
                    gc.forget.push(valid_root_key(&args[index])?);
                    index += 1;
                }
                if first == index {
                    return Err(UsageError::new(
                        "--forget needs at least one root key",
                        Some("gc"),
                    ));
                }
                continue;
            }
            _ if arg.starts_with("--forget=") => {
                gc.forget.push(valid_root_key(&arg["--forget=".len()..])?);
            }
            "--keep-days" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| UsageError::new("--keep-days needs <n>", Some("gc")))?;
                gc.keep_days = Some(parse_days(value)?);
                index += 1;
            }
            _ if arg.starts_with("--keep-days=") => {
                gc.keep_days = Some(parse_days(&arg["--keep-days=".len()..])?);
            }
            other => return Err(reject("gc", other)),
        }
        index += 1;
    }
    Ok(Some(Command::Gc(gc)))
}

fn parse_days(value: &str) -> Result<u64, UsageError> {
    value.parse().map_err(|_| {
        UsageError::new(
            format!("--keep-days expects a whole number of days, got '{value}'"),
            Some("gc"),
        )
    })
}

/// Root keys are registry file names: 40 hex characters. Rejecting anything
/// else here keeps `--forget` from ever acting on a guessed or malformed key.
/// The key is passed through exactly as typed: a registry key names one file,
/// so case-folding it here would aim `--forget` at a record the user did not
/// ask for whenever both spellings exist.
fn valid_root_key(value: &str) -> Result<String, UsageError> {
    let is_key = value.len() == 40 && value.bytes().all(|b| b.is_ascii_hexdigit());
    if is_key {
        Ok(value.to_string())
    } else {
        Err(UsageError::new(
            format!(
                "'{value}' is not a root key: expected 40 hex characters (`blanket store \
                 roots` prints keys)"
            ),
            Some("gc"),
        ))
    }
}

fn parse_store(args: &[String]) -> Result<Option<Command>, UsageError> {
    let command = match args.first().map(String::as_str) {
        Some("path") => Command::StorePath,
        Some("roots") => Command::StoreRoots,
        Some("-h" | "--help") => return Ok(None),
        None => {
            return Err(UsageError::new(
                "store needs a subcommand: 'store path' or 'store roots'",
                Some("store"),
            ))
        }
        Some(other) => {
            return Err(UsageError::new(
                with_suggestion(
                    format!("unknown store subcommand '{other}'"),
                    other,
                    ["path", "roots"].into_iter(),
                ),
                Some("store"),
            ))
        }
    };
    if let Some(extra) = args.get(1) {
        return Err(UsageError::new(
            format!("store {}: unexpected argument '{extra}'", args[0]),
            Some("store"),
        ));
    }
    Ok(Some(command))
}

fn parse_completions(args: &[String]) -> Result<Option<Command>, UsageError> {
    let shell = match args.first().map(String::as_str) {
        Some("bash") => Shell::Bash,
        Some("zsh") => Shell::Zsh,
        Some("fish") => Shell::Fish,
        Some("-h" | "--help") => return Ok(None),
        None => {
            return Err(UsageError::new(
                "completions needs a shell: bash, zsh, or fish",
                Some("completions"),
            ))
        }
        Some(other) => {
            return Err(UsageError::new(
                with_suggestion(
                    format!("unsupported shell '{other}' (bash, zsh, or fish)"),
                    other,
                    SHELL_WORDS.iter().copied(),
                ),
                Some("completions"),
            ))
        }
    };
    if let Some(extra) = args.get(1) {
        return Err(UsageError::new(
            format!("completions: unexpected argument '{extra}'"),
            Some("completions"),
        ));
    }
    Ok(Some(Command::Completions { shell }))
}

fn non_empty(
    value: &str,
    flag: &str,
    command: Option<&'static str>,
) -> Result<PathBuf, UsageError> {
    if value.is_empty() {
        return Err(UsageError::new(format!("{flag}= needs a value"), command));
    }
    Ok(PathBuf::from(value))
}

/// Unknown option or stray positional for a command with a fixed option set.
fn reject(name: &'static str, arg: &str) -> UsageError {
    let spec = spec(name).expect("known command");
    let message = if arg.starts_with('-') {
        with_suggestion(
            format!("{name}: unknown option '{arg}'"),
            flag_name(arg),
            spec.options
                .iter()
                .flat_map(|(flag, _)| option_spellings(flag)),
        )
    } else {
        format!("{name}: unexpected argument '{arg}'")
    };
    UsageError::new(message, Some(name))
}

/// `"-o, --output <file>"` → `["-o", "--output"]`.
pub fn option_spellings(flag: &'static str) -> impl Iterator<Item = &'static str> {
    flag.split(", ")
        .map(|part| part.split([' ', '=']).next().unwrap_or(part))
}

/// The flag without an inline `=value`.
fn flag_name(arg: &str) -> &str {
    arg.split('=').next().unwrap_or(arg)
}

fn with_suggestion<'a>(
    message: String,
    word: &str,
    candidates: impl Iterator<Item = &'a str>,
) -> String {
    match suggest(word, candidates) {
        Some(near) => format!("{message}; did you mean '{near}'?"),
        None => message,
    }
}

/// The closest candidate when it is close enough to be a typo: the same
/// word up to case or an `=value` suffix, a prefix relation (two characters
/// or more), or, for words of four characters or more, an edit distance of
/// at most one third of the word where an adjacent transposition counts as
/// one edit. Short words never get distance-based guesses: `-q` must not
/// become "did you mean -h".
pub fn suggest<'a>(word: &str, candidates: impl Iterator<Item = &'a str>) -> Option<&'a str> {
    let word = word.to_ascii_lowercase();
    let budget = if word.len() >= 4 {
        (word.len() / 3).max(1)
    } else {
        0
    };
    let mut best: Option<(usize, &str)> = None;
    for candidate in candidates {
        let lower = candidate.to_ascii_lowercase();
        let distance = if lower == word {
            0
        } else if word.len() >= 2 && (lower.starts_with(&word) || word.starts_with(&lower)) {
            0
        } else {
            edit_distance(&word, &lower)
        };
        if distance <= budget && best.map_or(true, |(d, _)| distance < d) {
            best = Some((distance, candidate));
        }
    }
    best.map(|(_, candidate)| candidate)
}

/// Optimal string alignment distance: Levenshtein plus adjacent
/// transposition as a single edit (`snyc` → `sync` is one).
fn edit_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let width = b.len() + 1;
    let mut d = vec![0usize; (a.len() + 1) * width];
    for i in 0..=a.len() {
        d[i * width] = i;
    }
    for j in 0..=b.len() {
        d[j] = j;
    }
    for i in 1..=a.len() {
        for j in 1..=b.len() {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            let mut best = (d[(i - 1) * width + j] + 1)
                .min(d[i * width + j - 1] + 1)
                .min(d[(i - 1) * width + j - 1] + cost);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                best = best.min(d[(i - 2) * width + j - 2] + 1);
            }
            d[i * width + j] = best;
        }
    }
    d[a.len() * width + b.len()]
}

/// Every option spelling a command accepts, `--help` included.
pub(super) fn command_flags(spec: &Spec) -> Vec<&'static str> {
    spec.options
        .iter()
        .flat_map(|(flag, _)| option_spellings(flag))
        .collect()
}

pub(super) fn all_command_words() -> Vec<&'static str> {
    COMMANDS
        .iter()
        .map(|spec| spec.name)
        .chain(SYNC_ALIASES.iter().copied())
        .chain(["help", "version"])
        .collect()
}

pub(super) const GLOBAL_FLAGS: &[&str] = &[
    "-C",
    "--directory",
    "-q",
    "--quiet",
    "-v",
    "--verbose",
    "--no-color",
    "-h",
    "--help",
    "-V",
    "--version",
];

#[cfg(test)]
mod tests {
    use super::super::render_usage_error;
    use super::*;

    fn argv(words: &[&str]) -> Vec<String> {
        words.iter().map(|word| word.to_string()).collect()
    }

    fn run(words: &[&str]) -> Invocation {
        match parse(&argv(words)).unwrap() {
            Parsed::Run(invocation) => invocation,
            other => panic!("expected a command, got {other:?}"),
        }
    }

    fn command(words: &[&str]) -> Command {
        run(words).command
    }

    fn printed(words: &[&str]) -> String {
        match parse(&argv(words)).unwrap() {
            Parsed::Print(text) => text,
            other => panic!("expected text, got {other:?}"),
        }
    }

    fn message(words: &[&str]) -> String {
        match parse(&argv(words)) {
            Err(error) => error.message,
            Ok(Parsed::Script { message, .. }) => message,
            Ok(other) => panic!("expected an error, got {other:?}"),
        }
    }

    #[test]
    fn no_command_is_implicit_and_keeps_the_options() {
        assert_eq!(parse(&[]), Ok(Parsed::Implicit(Options::default())));
        assert_eq!(
            parse(&argv(&["-C", "/tmp", "-q"])),
            Ok(Parsed::Implicit(Options {
                directory: Some(PathBuf::from("/tmp")),
                quiet: true,
                ..Options::default()
            }))
        );
    }

    #[test]
    fn unknown_first_word_is_a_script_candidate() {
        assert_eq!(
            parse(&argv(&["-v", "dev", "--port", "3000"])),
            Ok(Parsed::Script {
                options: Options {
                    verbose: true,
                    ..Options::default()
                },
                name: "dev".into(),
                args: argv(&["--port", "3000"]),
                message: "unknown command 'dev'".into(),
            })
        );
        assert_eq!(
            message(&["snyc"]),
            "unknown command 'snyc'; did you mean 'sync'?"
        );
        assert_eq!(
            message(&["sy"]),
            "unknown command 'sy'; did you mean 'sync'?"
        );
        assert_eq!(
            message(&["gcc"]),
            "unknown command 'gcc'; did you mean 'gc'?"
        );
        assert_eq!(message(&["deploy"]), "unknown command 'deploy'");
        assert_eq!(
            render_usage_error("unknown command 'deploy'", None),
            "blanket: error: unknown command 'deploy'\nRun 'blanket --help' for usage.\n"
        );
        assert_eq!(message(&["--fresh", "sync"]), "unknown option '--fresh'");
        assert_eq!(
            message(&["--dir", "x", "sync"]),
            "unknown option '--dir'; did you mean '--directory'?"
        );
    }

    #[test]
    fn help_and_version_at_every_level() {
        for words in [&["--help"][..], &["-h"], &["help"], &["help", "help"]] {
            assert_eq!(printed(words), usage(), "{words:?}");
        }
        for words in [
            &["--version"][..],
            &["-V"],
            &["version"],
            &["help", "version"],
        ] {
            assert_eq!(printed(words), format!("blanket {VERSION}\n"), "{words:?}");
        }
        for spec in COMMANDS {
            assert_eq!(
                printed(&["help", spec.name]),
                help(spec),
                "help {}",
                spec.name
            );
            assert_eq!(
                printed(&[spec.name, "--help"]),
                help(spec),
                "{} --help",
                spec.name
            );
            assert_eq!(printed(&[spec.name, "-h"]), help(spec), "{} -h", spec.name);
        }
        assert_eq!(printed(&["help", "install"]), help(spec("sync").unwrap()));
        assert_eq!(printed(&["i", "--help"]), help(spec("sync").unwrap()));
        assert_eq!(
            printed(&["gc", "--dry-run", "--help"]),
            help(spec("gc").unwrap())
        );
        assert_eq!(printed(&["-C", "/tmp", "--help"]), usage());
        assert!(message(&["help", "snyc"]).contains("did you mean 'sync'?"));
    }

    #[test]
    fn sync_flags_and_aliases() {
        let plain = Command::Sync {
            fresh: false,
            strict: false,
        };
        assert_eq!(command(&["sync"]), plain);
        assert_eq!(command(&["install"]), plain);
        assert_eq!(command(&["i"]), plain);
        assert_eq!(
            command(&["install", "--strict", "--fresh"]),
            Command::Sync {
                fresh: true,
                strict: true
            }
        );
        assert_eq!(
            message(&["sync", "--fersh"]),
            "sync: unknown option '--fersh'; did you mean '--fresh'?"
        );
        assert_eq!(
            message(&["i", "--strict=1"]),
            "sync: unknown option '--strict=1'; did you mean '--strict'?"
        );
        assert_eq!(message(&["sync", "now"]), "sync: unexpected argument 'now'");
        assert_eq!(
            parse(&argv(&["sync", "now"])).unwrap_err().render(),
            "blanket: error: sync: unexpected argument 'now'\nRun 'blanket help sync' for usage.\n"
        );
    }

    #[test]
    fn fmt_grammar_separates_blanket_flags_from_tool_args() {
        assert_eq!(
            command(&["fmt"]),
            Command::Fmt {
                check: false,
                ecosystem: None,
                args: vec![],
            }
        );
        assert_eq!(
            command(&["fmt", "--check", "--eco", "rust", "--edition", "2024"]),
            Command::Fmt {
                check: true,
                ecosystem: Some("rust".into()),
                args: argv(&["--edition", "2024"]),
            }
        );
        assert_eq!(
            command(&["fmt", "--", "--help"]),
            Command::Fmt {
                check: false,
                ecosystem: None,
                args: argv(&["--help"]),
            }
        );
        assert_eq!(
            message(&["fmt", "--chekc"]),
            "fmt: unknown option '--chekc'; did you mean '--check'?"
        );
        assert_eq!(
            command(&["fmt", "--eco=rust"]),
            Command::Fmt {
                check: false,
                ecosystem: Some("rust".into()),
                args: vec![],
            }
        );
        assert_eq!(message(&["fmt", "--eco"]), "fmt: --eco needs an ecosystem");
        // Both spellings reject a value that is really a mistyped flag.
        for args in [
            &["fmt", "--eco", "--check"][..],
            &["fmt", "--eco=--check"],
            &["fmt", "--eco="],
        ] {
            assert_eq!(message(args), "fmt: --eco needs an ecosystem", "{args:?}");
        }
    }

    #[test]
    fn plan_takes_nothing() {
        assert_eq!(command(&["plan"]), Command::Plan);
        assert_eq!(
            message(&["plan", "--json"]),
            "plan: unknown option '--json'"
        );
        assert_eq!(message(&["plan", "x"]), "plan: unexpected argument 'x'");
    }

    #[test]
    fn inspect_commands() {
        assert_eq!(command(&["status"]), Command::Status { json: false });
        assert_eq!(
            command(&["status", "--json"]),
            Command::Status { json: true }
        );
        assert_eq!(message(&["status", "-j"]), "status: unknown option '-j'");
        assert_eq!(
            command(&["audit"]),
            Command::Audit {
                policy: None,
                json: false
            }
        );
        assert_eq!(
            command(&["audit", "--policy", "company.toml", "--json"]),
            Command::Audit {
                policy: Some("company.toml".into()),
                json: true
            }
        );
        assert_eq!(
            command(&["audit", "--policy=company.toml"]),
            Command::Audit {
                policy: Some("company.toml".into()),
                json: false
            }
        );
        assert_eq!(
            message(&["audit", "--policy"]),
            "--policy needs a file path"
        );
        assert_eq!(message(&["audit", "--policy="]), "--policy= needs a value");
        assert_eq!(
            message(&["audit", "--policy", "--json"]),
            "--policy needs a file path"
        );
        assert_eq!(
            message(&["audit", "--policy=--json"]),
            "--policy needs a file path"
        );
        assert_eq!(
            message(&["audit", "--strict"]),
            "audit: unknown option '--strict'"
        );
        assert_eq!(
            message(&["audit", "python"]),
            "audit: unexpected argument 'python'"
        );
        assert!(printed(&["audit", "-h"]).contains("blanket audit [--policy <file>] [--json]"));
        assert_eq!(
            command(&["doctor", "--json"]),
            Command::Doctor { json: true }
        );
        assert_eq!(
            command(&["ls"]),
            Command::Ls {
                ecosystem: None,
                json: false
            }
        );
        assert_eq!(
            command(&["ls", "node", "--json"]),
            Command::Ls {
                ecosystem: Some("node".into()),
                json: true
            }
        );
        // The row `blanket fmt` makes `ls` print is a word `ls` accepts.
        assert_eq!(
            command(&["ls", "rustfmt"]),
            Command::Ls {
                ecosystem: Some("rustfmt".into()),
                json: false
            }
        );
        assert_eq!(
            message(&["ls", "npm"]),
            "ls: unknown ecosystem 'npm' (one of: python, node, cargo, go, ruby, elixir, dotnet, rustfmt)"
        );
        assert_eq!(
            message(&["ls", "pyhton"]),
            "ls: unknown ecosystem 'pyhton' (one of: python, node, cargo, go, ruby, elixir, dotnet, rustfmt); did you mean 'python'?"
        );
        assert_eq!(
            message(&["ls", "node", "python"]),
            "ls: unexpected argument 'python' (one ecosystem at most)"
        );
    }

    #[test]
    fn dependency_verbs() {
        assert_eq!(
            command(&["add", "requests>=2", "npm:react@18", "--dev", "--no-sync"]),
            Command::Add {
                specs: argv(&["requests>=2", "npm:react@18"]),
                dev: true,
                no_sync: true,
            }
        );
        assert!(message(&["add", "-D", "--", "-weird"])
            .contains("dependency spec '-weird' looks like a tool option"));
        assert!(message(&["add"]).starts_with("add: no package given"));
        assert_eq!(
            message(&["add", "--dve", "x"]),
            "add: unknown option '--dve'; did you mean '--dev'?"
        );
        assert_eq!(
            message(&["remove", "--dve", "x"]),
            "remove: unknown option '--dve'; did you mean '--dev'?"
        );
        assert_eq!(
            command(&["remove", "six", "--no-sync"]),
            Command::Remove {
                names: argv(&["six"]),
                dev: false,
                no_sync: true,
            }
        );
        assert_eq!(
            command(&["remove", "--dev", "six"]),
            Command::Remove {
                names: argv(&["six"]),
                dev: true,
                no_sync: false,
            }
        );
        assert_eq!(message(&["remove"]), "remove: no package given");
        assert_eq!(
            command(&["update"]),
            Command::Update {
                names: vec![],
                no_sync: false,
            }
        );
        assert_eq!(
            command(&["update", "serde", "tokio"]),
            Command::Update {
                names: argv(&["serde", "tokio"]),
                no_sync: false,
            }
        );
        for name in ["add", "remove", "update", "x"] {
            assert_eq!(printed(&[name, "--help"]), help(spec(name).unwrap()));
        }
    }

    #[test]
    fn x_owns_only_its_leading_flags() {
        assert_eq!(
            command(&["x", "ruff", "check", "--fix", "."]),
            Command::X {
                ecosystem: None,
                from: None,
                tool: "ruff".into(),
                args: argv(&["check", "--fix", "."]),
            }
        );
        assert_eq!(
            command(&["x", "--npm", "--from", "@angular/cli", "ng@18", "--version"]),
            Command::X {
                ecosystem: Some("node".into()),
                from: Some("@angular/cli".into()),
                tool: "ng@18".into(),
                args: argv(&["--version"]),
            }
        );
        assert_eq!(
            command(&["x", "py:cowsay@6.1", "hi"]),
            Command::X {
                ecosystem: Some("python".into()),
                from: None,
                tool: "cowsay@6.1".into(),
                args: argv(&["hi"]),
            }
        );
        assert!(message(&["x", "--", "--weird-tool"]).contains("x: invalid tool"));
        assert!(message(&["x"]).starts_with("x: no tool given"));
        assert_eq!(message(&["x", "--from"]), "--from needs a package name");
        assert_eq!(
            message(&["x", "--pyy", "ruff"]),
            "x: unknown option '--pyy'; did you mean '--py'?"
        );
        assert_eq!(
            command(&["x", "--clean"]),
            Command::XClean {
                ecosystem: None,
                from: None,
                tool: None,
            }
        );
        assert_eq!(
            command(&["x", "--clean", "--py", "ruff@0.6.1"]),
            Command::XClean {
                ecosystem: Some("python".into()),
                from: None,
                tool: Some("ruff@0.6.1".into()),
            }
        );
        assert_eq!(
            message(&["x", "--clean", "ruff", "extra"]),
            "x --clean: unexpected argument 'extra'"
        );
    }

    #[test]
    fn run_and_build_pass_arguments_through() {
        assert_eq!(
            command(&["run", "python", "-c", "print(1)", "--help"]),
            Command::Run {
                command: argv(&["python", "-c", "print(1)", "--help"])
            }
        );
        assert_eq!(
            command(&["run", "--", "-h"]),
            Command::Run {
                command: argv(&["-h"])
            }
        );
        assert_eq!(message(&["run"]), "run: no command given");
        assert_eq!(message(&["run", "--"]), "run: no command given");
        assert_eq!(command(&["build"]), Command::Build { args: vec![] });
        assert_eq!(command(&["build", "--"]), Command::Build { args: vec![] });
        assert_eq!(
            command(&["build", "cargo", "--release", "-h"]),
            Command::Build {
                args: argv(&["cargo", "--release", "-h"])
            }
        );
        assert_eq!(
            command(&["build", "--", "--help"]),
            Command::Build {
                args: argv(&["--help"])
            }
        );
        assert_eq!(
            command(&["build", "--release"]),
            Command::Build {
                args: argv(&["--release"])
            }
        );
    }

    #[test]
    fn sbom_output_spellings() {
        assert_eq!(command(&["sbom"]), Command::Sbom { output: None });
        for words in [
            &["sbom", "--output", "bom.json"][..],
            &["sbom", "-o", "bom.json"],
            &["sbom", "--output=bom.json"],
        ] {
            assert_eq!(
                command(words),
                Command::Sbom {
                    output: Some(PathBuf::from("bom.json"))
                },
                "{words:?}"
            );
        }
        assert_eq!(message(&["sbom", "--output"]), "--output needs a file path");
        assert_eq!(message(&["sbom", "--output="]), "--output= needs a value");
        assert_eq!(
            message(&["sbom", "--out", "x"]),
            "sbom: unknown option '--out'; did you mean '--output'?"
        );
        assert_eq!(
            message(&["sbom", "bom.json"]),
            "sbom: unexpected argument 'bom.json'"
        );
    }

    #[test]
    fn gc_options_keep_their_shapes() {
        assert_eq!(command(&["gc"]), Command::Gc(GcArgs::default()));
        assert_eq!(
            command(&[
                "gc",
                "--dry-run",
                "--keep-days",
                "0",
                "--register",
                "/a",
                "/b",
                "--project",
                "--register=/c",
                "--collect-legacy",
                "--keep-days=7",
            ]),
            Command::Gc(GcArgs {
                dry_run: true,
                keep_days: Some(7),
                project: true,
                collect_legacy: true,
                migrate_metadata: false,
                register: vec!["/a".into(), "/b".into(), "/c".into()],
                forget: Vec::new(),
            })
        );
        assert_eq!(
            message(&["gc", "--register"]),
            "--register needs at least one project directory"
        );
        assert_eq!(
            message(&["gc", "--register", "--dry-run"]),
            "--register needs at least one project directory"
        );
        assert_eq!(message(&["gc", "--register="]), "--register= needs a value");
        let key = "0123456789abcdef0123456789abcdef01234567";
        assert_eq!(
            command(&[
                "gc",
                "--forget",
                &key,
                "--forget=ABCDEF0123456789ABCDEF0123456789ABCDEF01"
            ]),
            Command::Gc(GcArgs {
                // Keys reach the store exactly as typed: one key names one
                // registry file, and both spellings can name records.
                forget: vec![
                    key.to_string(),
                    "ABCDEF0123456789ABCDEF0123456789ABCDEF01".to_string()
                ],
                ..GcArgs::default()
            })
        );
        assert_eq!(
            message(&["gc", "--forget"]),
            "--forget needs at least one root key"
        );
        assert_eq!(
            message(&["gc", "--forget", "nope"]),
            "'nope' is not a root key: expected 40 hex characters (`blanket store roots` \
             prints keys)"
        );
        assert_eq!(message(&["gc", "--keep-days"]), "--keep-days needs <n>");
        assert_eq!(
            message(&["gc", "--keep-days", "soon"]),
            "--keep-days expects a whole number of days, got 'soon'"
        );
        assert_eq!(
            message(&["gc", "--keep-days=-1"]),
            "--keep-days expects a whole number of days, got '-1'"
        );
        assert_eq!(
            message(&["gc", "--dryrun"]),
            "gc: unknown option '--dryrun'; did you mean '--dry-run'?"
        );
        assert_eq!(message(&["gc", "now"]), "gc: unexpected argument 'now'");
    }

    #[test]
    fn store_and_completions_words() {
        assert_eq!(command(&["store", "path"]), Command::StorePath);
        assert_eq!(command(&["store", "roots"]), Command::StoreRoots);
        assert_eq!(
            message(&["store"]),
            "store needs a subcommand: 'store path' or 'store roots'"
        );
        assert_eq!(
            message(&["store", "root"]),
            "unknown store subcommand 'root'; did you mean 'roots'?"
        );
        assert_eq!(
            message(&["store", "path", "x"]),
            "store path: unexpected argument 'x'"
        );
        assert_eq!(
            command(&["completions", "zsh"]),
            Command::Completions { shell: Shell::Zsh }
        );
        assert_eq!(
            message(&["completions"]),
            "completions needs a shell: bash, zsh, or fish"
        );
        assert_eq!(
            message(&["completions", "powershell"]),
            "unsupported shell 'powershell' (bash, zsh, or fish)"
        );
        assert_eq!(
            message(&["completions", "bas"]),
            "unsupported shell 'bas' (bash, zsh, or fish); did you mean 'bash'?"
        );
    }

    #[test]
    fn directory_option_spellings() {
        for words in [
            &["-C", "/work", "plan"][..],
            &["-C/work", "plan"],
            &["--directory", "/work", "plan"],
            &["--directory=/work", "plan"],
        ] {
            assert_eq!(
                run(words),
                Invocation {
                    options: Options {
                        directory: Some(PathBuf::from("/work")),
                        ..Options::default()
                    },
                    command: Command::Plan
                },
                "{words:?}"
            );
        }
        assert_eq!(run(&["plan"]).options, Options::default());
        assert_eq!(message(&["-C"]), "-C needs a directory");
        assert_eq!(message(&["--directory="]), "--directory= needs a value");
        assert_eq!(
            command(&["run", "make", "-C", "sub"]),
            Command::Run {
                command: argv(&["make", "-C", "sub"])
            }
        );
    }

    #[test]
    fn output_options_are_global_and_validated() {
        assert_eq!(
            run(&["-q", "-v", "--no-color", "-C", "/w", "plan"]).options,
            Options {
                directory: Some(PathBuf::from("/w")),
                quiet: true,
                verbose: true,
                no_color: true,
            }
        );
        assert!(run(&["--quiet", "--verbose", "plan"]).options.quiet);
        assert_eq!(
            message(&["--quite", "plan"]),
            "unknown option '--quite'; did you mean '--quiet'?"
        );
        assert_eq!(printed(&["-V"]), format!("blanket {VERSION}\n"));
        assert!(run(&["-v", "plan"]).options.verbose);
        assert_eq!(message(&["sync", "-q"]), "sync: unknown option '-q'");
        assert_eq!(
            command(&["run", "pytest", "-q"]),
            Command::Run {
                command: argv(&["pytest", "-q"])
            }
        );
    }

    #[test]
    fn suggestions_are_conservative() {
        let commands = || COMMANDS.iter().map(|spec| spec.name);
        assert_eq!(suggest("sync", commands()), Some("sync"));
        assert_eq!(suggest("SYNC", commands()), Some("sync"));
        assert_eq!(suggest("s", commands()), None);
        assert_eq!(suggest("gcx", commands()), Some("gc"));
        assert_eq!(suggest("gxc", commands()), None);
        assert_eq!(suggest("-q", ["-h", "-v"].into_iter()), None);
        assert_eq!(suggest("stor", commands()), Some("store"));
        assert_eq!(suggest("bulid", commands()), Some("build"));
        assert_eq!(suggest("snyc", commands()), Some("sync"));
        assert_eq!(suggest("deploy", commands()), None);
        assert_eq!(edit_distance("", "abc"), 3);
        assert_eq!(edit_distance("kitten", "sitting"), 3);
        assert_eq!(edit_distance("snyc", "sync"), 1);
        assert_eq!(edit_distance("ab", "ba"), 1);
    }
}

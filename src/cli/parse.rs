//! Turning argv into a `Parsed` invocation, one command at a time.

use std::path::PathBuf;

use super::spec::{
    canonical_name, help, spec, toolchain_section, usage, COMMANDS, LS_WORDS, SHELL_WORDS,
    SYNC_ALIASES, TOOLCHAIN_ALIAS, TOOLCHAIN_WORDS,
};
use super::{
    Command, GcArgs, Invocation, Options, Parsed, Shell, Spec, ToolchainUpdate, UsageError,
};

const VERSION_WORDS: [&str; 3] = ["-V", "--version", "version"];
const HELP_WORDS: [&str; 3] = ["-h", "--help", "help"];

fn version_text() -> String {
    format!("{}\n", super::version_line())
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
        if let Some(used) = global_flag(args, index, &mut options, None)? {
            index += used;
            continue;
        }
        if arg.starts_with('-') {
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
        break;
    }
    let Some(word) = args.get(index).map(String::as_str) else {
        return Ok(Parsed::Implicit(options));
    };
    let name = canonical_name(word);
    let rest = args[index + 1..].to_vec();
    // A global option is the same option wherever it appears, so every
    // command whose grammar owns its arguments accepts one after the verb
    // too. `run` and `build` hand everything after the verb to the program;
    // `fmt` and `x` own only the options that precede the tool's own
    // arguments; an unknown first word is a package.json script, and its
    // arguments are the script's.
    let rest = match spec(name) {
        _ if matches!(name, "run" | "build") => rest,
        Some(spec) => take_global_flags(&rest, &mut options, spec)?,
        None => rest,
    };
    let rest = &rest[..];
    let command = match name {
        "sync" => parse_sync(rest)?,
        "fmt" => parse_fmt(rest)?,
        "plan" => parse_plan(rest)?,
        "build" => parse_passthrough(rest, "build")?,
        "run" => parse_passthrough(rest, "run")?,
        "env" => parse_env(rest)?,
        "sbom" => parse_sbom(rest)?,
        "add" | "remove" | "update" => parse_deps(rest, name)?,
        "x" => parse_x(rest)?,
        "status" => parse_json_only(rest, "status")?.map(|json| Command::Status { json }),
        "audit" => parse_audit(rest)?,
        "ls" => parse_ls(rest)?,
        "doctor" => parse_json_only(rest, "doctor")?.map(|json| Command::Doctor { json }),
        "keygen" => parse_keygen(rest)?,
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

/// Read one global option at `args[index]`. `Ok(Some(n))` consumed `n`
/// arguments; `Ok(None)` when this argument is not a global option.
/// `command` is the verb whose help a complaint should point at, `None`
/// before the verb has been read.
fn global_flag(
    args: &[String],
    index: usize,
    options: &mut Options,
    command: Option<&'static str>,
) -> Result<Option<usize>, UsageError> {
    let arg = args[index].as_str();
    match arg {
        "-C" | "--directory" => {
            let value = separate_value(args, index, arg, command, "a directory")?;
            options.directory = Some(PathBuf::from(value));
            Ok(Some(2))
        }
        "-q" | "--quiet" => {
            options.quiet = true;
            Ok(Some(1))
        }
        "-v" | "--verbose" => {
            options.verbose = true;
            Ok(Some(1))
        }
        "--no-color" => {
            options.no_color = true;
            Ok(Some(1))
        }
        _ if arg.starts_with("--directory=") => {
            options.directory = Some(non_empty(
                &arg["--directory=".len()..],
                "--directory",
                command,
            )?);
            Ok(Some(1))
        }
        _ if arg.starts_with("-C") => {
            options.directory = Some(PathBuf::from(&arg[2..]));
            Ok(Some(1))
        }
        _ => Ok(None),
    }
}

/// Does this command's option take a value in the following argument(s)?
/// `Some(true)` for a list (`--register <dir>...`), `Some(false)` for a
/// single value (`--policy <file>`), `None` for a plain switch. Read from
/// the command table, so the answer cannot drift from the help text.
fn value_slot(spec: &Spec, arg: &str) -> Option<bool> {
    spec.options.iter().find_map(|(flag, _)| {
        (flag.contains('<') && option_spellings(flag).any(|spelling| spelling == arg))
            .then(|| flag.ends_with("..."))
    })
}

/// Is `arg` one of this command's own options? What ends a list of values.
fn is_command_option(spec: &Spec, arg: &str) -> bool {
    spec.options
        .iter()
        .any(|(flag, _)| option_spellings(flag).any(|spelling| spelling == flag_name(arg)))
}

/// Take every global option out of one command's arguments, leaving the
/// command's own grammar untouched. Three things are never looked inside:
/// everything after `--`; for a command that ends in a tool's own arguments
/// (`fmt`, `x`), everything from its first non-option word on; and the value
/// slot of one of the command's own value-taking options, so `-v` in a slot
/// reaches that option's own grammar rather than becoming `--verbose`. What
/// the option then makes of it is its own business: a list option
/// (`--register <dir>...`) holds its slot until the next long option and
/// takes `-v` as a directory name, while an option taking a single value
/// refuses it under `separate_value`.
fn take_global_flags(
    args: &[String],
    options: &mut Options,
    spec: &'static Spec,
) -> Result<Vec<String>, UsageError> {
    let leading = matches!(spec.name, "fmt" | "x");
    let mut rest = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = args[index].as_str();
        if arg == "--" || (leading && !arg.starts_with('-')) {
            rest.extend_from_slice(&args[index..]);
            break;
        }
        if let Some(list) = value_slot(spec, arg) {
            rest.push(args[index].clone());
            index += 1;
            let mut taken = 0;
            while index < args.len() && (list || taken == 0) {
                let value = args[index].as_str();
                // A list ends where the command's own parser ends it: at
                // the next long option, so `gc --register /p --no-color`
                // still reads the global rather than refusing it.
                let ends = value == "--"
                    || (list && value.starts_with("--"))
                    || (taken > 0 && is_command_option(spec, value));
                if ends {
                    break;
                }
                rest.push(args[index].clone());
                index += 1;
                taken += 1;
            }
            continue;
        }
        match global_flag(args, index, options, Some(spec.name))? {
            Some(used) => index += used,
            None => {
                rest.push(args[index].clone());
                index += 1;
            }
        }
    }
    Ok(rest)
}

fn help_topic(topic: Option<&str>) -> Result<String, UsageError> {
    match topic {
        None => Ok(usage()),
        Some(name) if HELP_WORDS.contains(&name) => Ok(usage()),
        Some(name) if VERSION_WORDS.contains(&name) => Ok(version_text()),
        Some(name) => spec(name).map(help).ok_or_else(|| {
            UsageError::new(
                with_suggestion(
                    format!("no help for '{name}': not a tog command"),
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
    let mut frozen = false;
    for arg in args {
        match arg.as_str() {
            "--fresh" => fresh = true,
            "--strict" => strict = true,
            "--frozen" => frozen = true,
            "-h" | "--help" => return Ok(None),
            other if !other.starts_with('-') => {
                return Err(UsageError::new(sync_takes_no_package(other), Some("sync")))
            }
            other => return Err(reject("sync", other)),
        }
    }
    Ok(Some(Command::Sync {
        fresh,
        strict,
        frozen,
    }))
}

/// `tog install requests` is the first thing a pip or npm user types, and
/// `install` is an alias for `sync`, which takes no package. Name the verb
/// that does instead of rejecting the word.
fn sync_takes_no_package(package: &str) -> String {
    format!(
        "sync: unexpected argument '{package}'; sync realizes what the project already declares \
         — to add a dependency run 'tog add {package}'"
    )
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
                let value = separate_value(args, index, "fmt: --eco", Some("fmt"), "an ecosystem")?;
                ecosystem = Some(value.to_string());
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

/// `plan` already prints JSON, so `--json` is accepted and only promises
/// what every `--json` command promises: nothing but JSON on stdout, and a
/// JSON error object on stderr when it fails.
fn parse_plan(args: &[String]) -> Result<Option<Command>, UsageError> {
    Ok(parse_json_only(args, "plan")?.map(|json| Command::Plan { json }))
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
            // file name; a policy file whose name starts with a dash is
            // named inline, as `--policy=-x.toml`.
            "--policy" => {
                let value = separate_value(args, index, arg, Some("audit"), "a file path")?;
                policy = Some(PathBuf::from(value));
                index += 1;
            }
            _ if arg.starts_with("--policy=") => {
                policy = Some(non_empty(
                    &arg["--policy=".len()..],
                    "--policy",
                    Some("audit"),
                )?);
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
    let mut toolchain = false;
    let mut self_update = false;
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
            "--toolchain" if name == "update" => toolchain = true,
            "--self" if name == "update" => self_update = true,
            "--dev" | "-D" if matches!(name, "add" | "remove") => dev = true,
            other if other.starts_with('-') && other.len() > 1 => return Err(reject(name, other)),
            other => {
                // A word after --toolchain names an ecosystem, not a
                // package, so the dependency-spec grammar must not judge it.
                if toolchain {
                    positional.push(other.to_string());
                    continue;
                }
                validate_dependency_arg(name, other)?;
                positional.push(other.to_string());
            }
        }
    }
    if self_update {
        // `--self` updates tog itself and nothing in the project, so a
        // package, `--toolchain`, or `--no-sync` beside it has no meaning.
        let stray = if toolchain {
            Some("--toolchain".to_string())
        } else if no_sync {
            Some("--no-sync".to_string())
        } else {
            positional.first().map(|word| format!("'{word}'"))
        };
        if let Some(stray) = stray {
            return Err(UsageError::new(
                format!(
                    "update --self replaces the tog binary and takes nothing else; drop {stray}"
                ),
                Some("update"),
            ));
        }
        return Ok(Some(Command::SelfUpdate));
    }
    if toolchain {
        return parse_update_toolchain(&positional, no_sync).map(Some);
    }

    match name {
        "add" if positional.is_empty() => Err(UsageError::new(
            "add: no package given (e.g. 'tog add requests', 'tog add npm:react@18')",
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
            toolchain: None,
        })),
    }
}

/// `update --toolchain [<ecosystem>]`. It is a different verb wearing the
/// same word: it re-selects a toolchain and never edits a dependency lock,
/// so the one positional it takes is an ecosystem and a package name is
/// refused by name rather than delegated to a tool that would not know what
/// to do with it.
fn parse_update_toolchain(positional: &[String], no_sync: bool) -> Result<Command, UsageError> {
    let ecosystem = match positional {
        [] => None,
        [word] => match toolchain_section(word) {
            Some(section) => Some(section.to_string()),
            None => return Err(not_an_ecosystem(word)),
        },
        [_, word, ..] => return Err(not_an_ecosystem(word)),
    };
    Ok(Command::Update {
        names: Vec::new(),
        no_sync,
        toolchain: Some(ToolchainUpdate { ecosystem }),
    })
}

fn not_an_ecosystem(word: &str) -> UsageError {
    UsageError::new(
        with_suggestion(
            format!(
                "update --toolchain takes an ecosystem name, not a package; '{word}' is not one \
                 of {}",
                TOOLCHAIN_WORDS.join(", ")
            ),
            word,
            TOOLCHAIN_WORDS
                .iter()
                .copied()
                .chain(std::iter::once(TOOLCHAIN_ALIAS)),
        ),
        Some("update"),
    )
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
    crate::commands::deps::validate_spec(arg)
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
                let value = separate_value(args, index, arg, Some("x"), "a package name")?;
                validate_x_package(value)?;
                from = Some(value.to_string());
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
            "x: no tool given (e.g. 'tog x ruff check .', 'tog x npm:prettier --write .')",
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
    // never be accepted as a package name. Version text is checked by
    // `validate_x_version_pair`; these checks keep argv errors at exit 2.
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

fn parse_keygen(args: &[String]) -> Result<Option<Command>, UsageError> {
    let mut path = None;
    let mut literal = false;
    for arg in args {
        match arg.as_str() {
            "-h" | "--help" if !literal => return Ok(None),
            // `--` ends option parsing, so a path that starts with `-` can
            // be given.
            "--" if !literal => literal = true,
            other if !literal && other.starts_with('-') => return Err(reject("keygen", other)),
            other => {
                if path.is_some() {
                    return Err(UsageError::new(
                        format!("keygen: unexpected argument '{other}'"),
                        Some("keygen"),
                    ));
                }
                if other.is_empty() {
                    return Err(UsageError::new(
                        "keygen: the key path is empty",
                        Some("keygen"),
                    ));
                }
                path = Some(PathBuf::from(other));
            }
        }
    }
    match path {
        Some(path) => Ok(Some(Command::Keygen { path })),
        None => Err(UsageError::new(
            "keygen needs the path to write the key to",
            Some("keygen"),
        )),
    }
}

fn parse_sbom(args: &[String]) -> Result<Option<Command>, UsageError> {
    let mut output = None;
    let mut index = 0;
    while let Some(arg) = args.get(index).map(String::as_str) {
        match arg {
            "-h" | "--help" => return Ok(None),
            // Both spellings take the same value through the same rule, so
            // neither an empty path nor an option-shaped one can slip in by
            // being written as two words.
            "-o" | "--output" => {
                let value = separate_value(args, index, arg, Some("sbom"), "a file path")?;
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
            "--drop-object" => {
                index += 1;
                let first = index;
                while index < args.len() && !args[index].starts_with("--") {
                    gc.drop_objects.push(valid_object_id(&args[index])?);
                    index += 1;
                }
                if first == index {
                    return Err(UsageError::new(
                        "--drop-object needs at least one store object id",
                        Some("gc"),
                    ));
                }
                continue;
            }
            _ if arg.starts_with("--drop-object=") => {
                gc.drop_objects
                    .push(valid_object_id(&arg["--drop-object=".len()..])?);
            }
            "--keep-days" => {
                let value = separate_value(args, index, arg, Some("gc"), "<n>")?;
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
                "'{value}' is not a root key: expected 40 hex characters (`tog store \
                 roots` prints keys)"
            ),
            Some("gc"),
        ))
    }
}

/// Object ids are store directory names: 40 hex characters, a hyphen, then
/// the name and version. Checking the shape in argv keeps `--drop-object`
/// from ever handing a path-shaped or traversing value to a removal path.
///
/// The rule is spelled out here rather than called from the kernel because
/// the CLI layer may not reach into it (ARCHITECTURE.md, layering rule 1);
/// `store::is_object_id` remains the authority, and the kernel re-checks
/// every id it is given.
fn valid_object_id(value: &str) -> Result<String, UsageError> {
    let bytes = value.as_bytes();
    let well_formed = bytes.len() > 41
        && bytes[..40].iter().all(u8::is_ascii_hexdigit)
        && bytes[40] == b'-'
        && !value.contains("..")
        && bytes[41..]
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'.' || *b == b'_' || *b == b'-');
    if well_formed {
        Ok(value.to_string())
    } else {
        Err(UsageError::new(
            format!("--drop-object expects a store object id (<40 hex>-<name>-<version>), got '{value}'"),
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

/// One shell vocabulary for the two commands that take one, so
/// `tog completions <shell>` and `tog env --shell <shell>` cannot come to
/// disagree about what a shell is or how a typo is answered.
fn named_shell(word: &str, command: &'static str) -> Result<Shell, UsageError> {
    match word {
        "bash" => Ok(Shell::Bash),
        "zsh" => Ok(Shell::Zsh),
        "fish" => Ok(Shell::Fish),
        other => Err(UsageError::new(
            with_suggestion(
                format!("unsupported shell '{other}' (bash, zsh, or fish)"),
                other,
                SHELL_WORDS.iter().copied(),
            ),
            Some(command),
        )),
    }
}

/// `env [--shell <bash|zsh|fish>]`. No `--shell` leaves the choice to the
/// command, which reads `$SHELL`; the grammar never looks at the host.
fn parse_env(args: &[String]) -> Result<Option<Command>, UsageError> {
    let mut shell = None;
    let mut index = 0;
    while let Some(arg) = args.get(index).map(String::as_str) {
        match arg {
            "-h" | "--help" => return Ok(None),
            // A mistyped flag (`--shell --json`) is a usage error, not a
            // shell name, by the same rule every value-taking option uses.
            "--shell" => {
                let value = separate_value(args, index, "env: --shell", Some("env"), "a shell")?;
                shell = Some(named_shell(value, "env")?);
                index += 1;
            }
            _ if arg.starts_with("--shell=") => {
                shell = Some(named_shell(&arg["--shell=".len()..], "env")?);
            }
            other => return Err(reject("env", other)),
        }
        index += 1;
    }
    Ok(Some(Command::Env { shell }))
}

fn parse_completions(args: &[String]) -> Result<Option<Command>, UsageError> {
    let shell = match args.first().map(String::as_str) {
        Some("-h" | "--help") => return Ok(None),
        None => {
            return Err(UsageError::new(
                "completions needs a shell: bash, zsh, or fish",
                Some("completions"),
            ))
        }
        Some(word) => named_shell(word, "completions")?,
    };
    if let Some(extra) = args.get(1) {
        return Err(UsageError::new(
            format!("completions: unexpected argument '{extra}'"),
            Some("completions"),
        ));
    }
    Ok(Some(Command::Completions { shell }))
}

/// The value of a value-taking flag written as a separate word. One rule
/// for all of them: the value must be there, must not be empty, and must not
/// start with `-`, so `tog sbom -o --json` is the mistyped flag it looks like
/// rather than a file named `--json`. A value that really does start with a
/// dash is given inline instead, as `--output=-x`.
fn separate_value<'a>(
    args: &'a [String],
    index: usize,
    flag: &str,
    command: Option<&'static str>,
    needs: &str,
) -> Result<&'a str, UsageError> {
    args.get(index + 1)
        .map(String::as_str)
        .filter(|value| !value.is_empty() && !value.starts_with('-'))
        .ok_or_else(|| UsageError::new(format!("{flag} needs {needs}"), command))
}

/// The inline `--flag=value` half of the same rule: the `=` already says
/// where the value begins, so only an empty one is refused here. What the
/// value may contain is each flag's own business.
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
            "tog: error: unknown command 'deploy'\nRun 'tog --help' for usage.\n"
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
            assert_eq!(
                printed(words),
                format!("{}\n", super::super::version_line()),
                "{words:?}"
            );
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
            frozen: false,
        };
        assert_eq!(command(&["sync"]), plain);
        assert_eq!(command(&["install"]), plain);
        assert_eq!(command(&["i"]), plain);
        assert_eq!(
            command(&["install", "--strict", "--fresh"]),
            Command::Sync {
                fresh: true,
                strict: true,
                frozen: false
            }
        );
        // `--frozen` is the same flag under every alias, because the
        // alias is resolved before the command's own grammar runs.
        for word in ["sync", "install", "i"] {
            assert_eq!(
                command(&[word, "--frozen"]),
                Command::Sync {
                    fresh: false,
                    strict: false,
                    frozen: true
                },
                "{word}"
            );
        }
        assert_eq!(
            message(&["sync", "--fersh"]),
            "sync: unknown option '--fersh'; did you mean '--fresh'?"
        );
        assert_eq!(
            message(&["i", "--strict=1"]),
            "sync: unknown option '--strict=1'; did you mean '--strict'?"
        );
        // A positional is almost always a package name: `tog install
        // requests` from a pip or npm habit. Name the verb that takes one.
        for argv_words in [
            ["install", "requests"],
            ["i", "requests"],
            ["sync", "requests"],
        ] {
            let message = message(&argv_words);
            assert!(
                message.contains("tog add requests"),
                "{argv_words:?}: {message}"
            );
        }
        assert_eq!(
            parse(&argv(&["sync", "now"])).unwrap_err().render(),
            format!(
                "tog: error: {}\nRun 'tog help sync' for usage.\n",
                sync_takes_no_package("now")
            )
        );
    }

    #[test]
    fn fmt_grammar_separates_tog_flags_from_tool_args() {
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

    /// `plan` prints JSON, so it accepts the flag that says so.
    #[test]
    fn plan_takes_only_json() {
        assert_eq!(command(&["plan"]), Command::Plan { json: false });
        assert_eq!(command(&["plan", "--json"]), Command::Plan { json: true });
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
        // The inline form is the escape hatch for a value that starts
        // with a dash, so it names a file rather than refusing.
        assert_eq!(
            command(&["audit", "--policy=--json"]),
            Command::Audit {
                policy: Some("--json".into()),
                json: false
            }
        );
        assert_eq!(
            message(&["audit", "--policy", ""]),
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
        assert!(printed(&["audit", "-h"]).contains("tog audit [--policy <file>] [--json]"));
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
        // The row `tog fmt` makes `ls` print is a word `ls` accepts.
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
                toolchain: None,
            }
        );
        assert_eq!(
            command(&["update", "serde", "tokio"]),
            Command::Update {
                names: argv(&["serde", "tokio"]),
                no_sync: false,
                toolchain: None,
            }
        );
        // `--toolchain` is the other update: no package names, and the
        // ecosystem word is the lock's section key, with `cargo` accepted
        // as the name every other verb uses for it.
        assert_eq!(
            command(&["update", "--toolchain"]),
            Command::Update {
                names: vec![],
                no_sync: false,
                toolchain: Some(ToolchainUpdate { ecosystem: None }),
            }
        );
        assert_eq!(
            command(&["update", "--toolchain", "cargo", "--no-sync"]),
            Command::Update {
                names: vec![],
                no_sync: true,
                toolchain: Some(ToolchainUpdate {
                    ecosystem: Some("rust".into())
                }),
            }
        );
        assert!(message(&["update", "--toolchain", "serde"])
            .contains("takes an ecosystem name, not a package"));
        assert!(message(&["update", "serde", "--toolchain"])
            .contains("takes an ecosystem name, not a package"));
        assert!(message(&["update", "--toolchain", "python", "node"])
            .contains("takes an ecosystem name, not a package"));
        // `--self` is a third verb wearing the word: nothing goes with it.
        assert_eq!(command(&["update", "--self"]), Command::SelfUpdate);
        for (words, stray) in [
            (&["update", "--self", "serde"][..], "'serde'"),
            (&["update", "serde", "--self"], "'serde'"),
            (&["update", "--self", "--toolchain"], "--toolchain"),
            (&["update", "--toolchain", "--self"], "--toolchain"),
            (&["update", "--self", "--no-sync"], "--no-sync"),
        ] {
            let text = message(words);
            assert!(
                text.contains("update --self replaces the tog binary") && text.contains(stray),
                "{words:?}: {text}"
            );
        }
        for name in ["add", "remove"] {
            assert!(
                message(&[name, "--self", "six"]).contains("unknown option '--self'"),
                "{name}"
            );
        }
        // `--toolchain` is not an option of the dependency verbs.
        assert_eq!(
            message(&["add", "--toolchain"]),
            "add: unknown option '--toolchain'"
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
        // The one rule, through either spelling: a value written as a
        // separate word is never empty and never starts with a dash, so
        // neither an empty path nor a mistyped flag becomes a file name.
        for words in [
            &["sbom", "-o", "--json"][..],
            &["sbom", "-o", ""],
            &["sbom", "-o", "-v"],
        ] {
            assert_eq!(message(words), "-o needs a file path", "{words:?}");
        }
        for words in [
            &["sbom", "--output", "--json"][..],
            &["sbom", "--output", ""],
        ] {
            assert_eq!(message(words), "--output needs a file path", "{words:?}");
        }
        // The inline form is how a path that really starts with a dash is
        // given.
        assert_eq!(
            command(&["sbom", "--output=-report.json"]),
            Command::Sbom {
                output: Some(PathBuf::from("-report.json"))
            }
        );
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
                drop_objects: Vec::new(),
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
            "'nope' is not a root key: expected 40 hex characters (`tog store roots` \
             prints keys)"
        );
        let object = format!("{}-cpython-3.11.9", "a".repeat(40));
        let other = format!("{}-ruff-0.6.9", "b".repeat(40));
        assert_eq!(
            command(&[
                "gc",
                "--drop-object",
                &object,
                &format!("--drop-object={other}")
            ]),
            Command::Gc(GcArgs {
                drop_objects: vec![object.clone(), other],
                ..GcArgs::default()
            })
        );
        assert_eq!(
            message(&["gc", "--drop-object"]),
            "--drop-object needs at least one store object id"
        );
        assert_eq!(
            message(&["gc", "--drop-object", "--dry-run"]),
            "--drop-object needs at least one store object id"
        );
        assert_eq!(
            message(&["gc", "--drop-object", "cpython"]),
            "--drop-object expects a store object id (<40 hex>-<name>-<version>), got 'cpython'"
        );
        assert_eq!(
            message(&["gc", "--drop-object="]),
            "--drop-object expects a store object id (<40 hex>-<name>-<version>), got ''"
        );
        let traversal = format!("{}-../escape", "a".repeat(40));
        assert_eq!(
            message(&["gc", "--drop-object", &traversal]),
            format!(
                "--drop-object expects a store object id (<40 hex>-<name>-<version>), got \
                 '{traversal}'"
            )
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

    /// `env` takes one optional shell and nothing else. No `--shell` is
    /// `None` here on purpose: the default reads `$SHELL`, which the
    /// grammar may not look at.
    #[test]
    fn env_takes_a_shell_and_nothing_else() {
        assert_eq!(command(&["env"]), Command::Env { shell: None });
        assert_eq!(
            command(&["env", "--shell", "fish"]),
            Command::Env {
                shell: Some(Shell::Fish)
            }
        );
        assert_eq!(
            command(&["env", "--shell=zsh"]),
            Command::Env {
                shell: Some(Shell::Zsh)
            }
        );
        // The same vocabulary and the same typo answer as `completions`.
        assert_eq!(
            message(&["env", "--shell", "powershell"]),
            "unsupported shell 'powershell' (bash, zsh, or fish)"
        );
        assert_eq!(
            message(&["env", "--shell", "fis"]),
            "unsupported shell 'fis' (bash, zsh, or fish); did you mean 'fish'?"
        );
        assert_eq!(message(&["env", "--shell"]), "env: --shell needs a shell");
        assert_eq!(
            message(&["env", "extra"]),
            "env: unexpected argument 'extra'"
        );
        assert_eq!(
            message(&["env", "--shel", "fish"]),
            "env: unknown option '--shel'; did you mean '--shell'?"
        );
        assert!(printed(&["env", "-h"]).starts_with("tog env — "));
        assert_eq!(printed(&["env", "--help"]), printed(&["help", "env"]));
        // Not a pass-through verb: a global option works on either side.
        for words in [&["-q", "env"][..], &["env", "-q"]] {
            assert_eq!(
                run(words),
                Invocation {
                    options: Options {
                        quiet: true,
                        ..Options::default()
                    },
                    command: Command::Env { shell: None },
                },
                "{words:?}"
            );
        }
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
            // The same option, after the command.
            &["plan", "-C", "/work"],
            &["plan", "--directory=/work"],
        ] {
            assert_eq!(
                run(words),
                Invocation {
                    options: Options {
                        directory: Some(PathBuf::from("/work")),
                        ..Options::default()
                    },
                    command: Command::Plan { json: false }
                },
                "{words:?}"
            );
        }
        assert_eq!(run(&["plan"]).options, Options::default());
        assert_eq!(message(&["-C"]), "-C needs a directory");
        assert_eq!(message(&["--directory="]), "--directory= needs a value");
        for words in [&["-C", "", "plan"][..], &["-C", "-q", "plan"]] {
            assert_eq!(message(words), "-C needs a directory", "{words:?}");
        }
        assert_eq!(
            message(&["plan", "--directory", "--json"]),
            "--directory needs a directory"
        );
        assert_eq!(
            run(&["--directory=-work", "plan"]).options.directory,
            Some(PathBuf::from("-work"))
        );
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
        assert_eq!(
            printed(&["-V"]),
            format!("{}\n", super::super::version_line())
        );
        assert!(run(&["-v", "plan"]).options.verbose);
        assert_eq!(
            command(&["run", "pytest", "-q"]),
            Command::Run {
                command: argv(&["pytest", "-q"])
            }
        );
    }

    /// A value belongs to the flag that takes it. The global scan that
    /// lifts `-q` out of a command's arguments must step over a value-taking
    /// flag's value, or it turns a mistyped flag into a missing one and, for
    /// `x --from`, silently promotes the tool name to the package name.
    #[test]
    fn the_global_scan_steps_over_a_flags_value() {
        assert_eq!(
            message(&["x", "--from", "-q", "ruff"]),
            "--from needs a package name"
        );
        assert_eq!(
            message(&["fmt", "--eco", "-q"]),
            "fmt: --eco needs an ecosystem"
        );
        // A value that is not a flag is still the flag's, and a global
        // typed after it is still taken.
        let parsed = run(&["sbom", "-o", "bom.json", "-q"]);
        assert!(parsed.options.quiet);
        assert_eq!(
            parsed.command,
            Command::Sbom {
                output: Some(PathBuf::from("bom.json"))
            }
        );
        let parsed = run(&["x", "--from", "black", "-q", "black"]);
        assert!(parsed.options.quiet);
        assert_eq!(
            parsed.command,
            Command::X {
                ecosystem: None,
                from: Some("black".into()),
                tool: "black".into(),
                args: Vec::new()
            }
        );
    }

    /// A global option means the same thing wherever it is typed, so the
    /// position it is typed in is not a usage error.
    #[test]
    fn global_options_are_accepted_after_the_command() {
        assert!(run(&["sync", "-q"]).options.quiet);
        assert_eq!(
            command(&["sync", "-q", "--fresh"]),
            Command::Sync {
                fresh: true,
                strict: false,
                frozen: false
            }
        );
        assert!(run(&["ls", "-v"]).options.verbose);
        assert_eq!(
            command(&["ls", "-v", "python"]),
            Command::Ls {
                ecosystem: Some("python".into()),
                json: false
            }
        );
        assert!(run(&["status", "--json", "--no-color"]).options.no_color);
        assert_eq!(
            run(&["gc", "--dry-run", "--directory=/w"])
                .options
                .directory,
            Some(PathBuf::from("/w"))
        );
        // Pass-through is still sacred: `run` and `build` hand every
        // argument to the program, and `fmt`/`x` stop at the tool's own.
        assert!(!run(&["run", "pytest", "-q"]).options.quiet);
        assert!(!run(&["x", "ruff", "-q"]).options.quiet);
        assert!(run(&["x", "-q", "ruff"]).options.quiet);
        assert_eq!(
            command(&["x", "-q", "ruff", "-q"]),
            Command::X {
                ecosystem: None,
                from: None,
                tool: "ruff".into(),
                args: argv(&["-q"])
            }
        );
        assert!(!run(&["fmt", "--", "-v"]).options.verbose);
        assert!(run(&["fmt", "-v", "--check"]).options.verbose);
        // An unknown option is still an unknown option.
        assert_eq!(message(&["sync", "-j"]), "sync: unknown option '-j'");

        // The value slot of the command's own option is not searched, so
        // `-v` reaches sbom's own grammar. There it is refused: a value
        // written as a separate word never starts with a dash, and
        // `--output=-v` is how a file really called that is named.
        assert_eq!(message(&["sbom", "-o", "-v"]), "-o needs a file path");
        assert_eq!(
            command(&["sbom", "--output=-v"]),
            Command::Sbom {
                output: Some(PathBuf::from("-v"))
            }
        );
        // `audit` refuses an option-shaped policy name itself, and still
        // does: the value slot reaches its own grammar, not the global one.
        assert_eq!(
            message(&["audit", "--policy", "-q"]),
            "--policy needs a file path"
        );
        assert!(!run(&["sbom", "-o", "bom.json"]).options.verbose);
        assert_eq!(
            message(&["gc", "--keep-days", "-v"]),
            "--keep-days needs <n>"
        );
        // A list option holds its slot for every value, the same boundary
        // gc's own parser uses: a directory may be called '-v' too.
        let parsed = run(&["gc", "--register", "a", "-v", "b"]);
        assert!(!parsed.options.verbose);
        assert_eq!(
            parsed.command,
            Command::Gc(GcArgs {
                register: vec![PathBuf::from("a"), PathBuf::from("-v"), PathBuf::from("b")],
                ..GcArgs::default()
            })
        );
        // A long option ends the list, the same boundary parse_gc uses,
        // so a global after a list of values is still read as a global.
        let parsed = run(&["gc", "--register", "/p", "--no-color"]);
        assert!(parsed.options.no_color);
        assert_eq!(
            parsed.command,
            Command::Gc(GcArgs {
                register: vec![PathBuf::from("/p")],
                ..GcArgs::default()
            })
        );
        assert_eq!(
            run(&["gc", "--register", "/p", "--directory", "/tmp"])
                .options
                .directory,
            Some(PathBuf::from("/tmp"))
        );
        // The next option this command knows still ends the list.
        let parsed = run(&["gc", "--register", "a", "--dry-run", "-v"]);
        assert!(parsed.options.verbose);
        assert_eq!(
            parsed.command,
            Command::Gc(GcArgs {
                register: vec![PathBuf::from("a")],
                dry_run: true,
                ..GcArgs::default()
            })
        );

        // A global option that is wrong after the verb points at that
        // command's help, not at the top-level usage.
        let error = parse(&argv(&["status", "-C"])).unwrap_err();
        assert_eq!(error.message, "-C needs a directory");
        assert_eq!(error.command, Some("status"));
        let error = parse(&argv(&["-C"])).unwrap_err();
        assert_eq!(error.command, None);
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

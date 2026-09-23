//! The Python tailor's `tog run` refusals (`Tailor::refused_command`):
//! `pip install` and its relatives cannot write into a projected `.venv`.

/// The pip subcommands that try to write into the environment. Reading
/// commands (`pip list`, `pip freeze`, `pip show`, `pip check`) work
/// against a projected .venv and are none of tog's business.
const PIP_MUTATING_VERBS: &[&str] = &["install", "uninstall", "wheel"];

/// Every pip subcommand, so an option's *value* is never mistaken for one.
/// `pip --index-url x install y` has two bare words before the package;
/// taking the first would read the URL as the subcommand and let an
/// install through.
const PIP_SUBCOMMANDS: &[&str] = &[
    "install",
    "uninstall",
    "wheel",
    "download",
    "freeze",
    "inspect",
    "list",
    "show",
    "check",
    "config",
    "search",
    "cache",
    "index",
    "hash",
    "completion",
    "debug",
    "help",
];

/// pip's subcommand: the first word that is one, wherever it sits among
/// the global options.
fn pip_subcommand(cmd: &[String], from: usize) -> &str {
    cmd.iter()
        .skip(from)
        .map(String::as_str)
        .find(|word| PIP_SUBCOMMANDS.contains(word))
        .unwrap_or_default()
}

/// Python options that take a separate value, so the value is not mistaken
/// for the script name when looking for `-m`.
const PYTHON_VALUE_OPTIONS: &[&str] = &["-X", "-W", "-Q", "--check-hash-based-pycs"];

/// `python -m pip install ...` reaches the same pip by another road.
///
/// `-m` is only python's while it is still an option: in
/// `python script.py -m pip install x` the `-m` belongs to the script, and
/// refusing that would refuse a program tog knows nothing about.
fn python_module_pip_verb(cmd: &[String]) -> Option<&str> {
    let program = cmd.first()?.rsplit('/').next()?;
    if !program.starts_with("python") {
        return None;
    }
    let mut index = 1;
    while let Some(word) = cmd.get(index).map(String::as_str) {
        if word == "-m" {
            // `-m <module>` ends python's own options.
            if cmd.get(index + 1).map(String::as_str)? != "pip" {
                return None;
            }
            return Some(pip_subcommand(cmd, index + 2));
        }
        if !word.starts_with('-') {
            // The script or the `-c` program: everything after is its own.
            return None;
        }
        index += if PYTHON_VALUE_OPTIONS.contains(&word) {
            2
        } else {
            1
        };
    }
    None
}

fn pip_refusal(program: &str, verb: &str) -> String {
    format!(
        "'{program} {verb}' cannot change a tog environment: .venv is a projection of an \
         immutable store object, so nothing can be installed into or removed from it. Add the \
         dependency instead ('tog add <package>', 'tog remove <package>'), then \
         'tog run python ...'"
    )
}

/// `pip install` finds no pip in a projected `.venv` and reports a missing
/// file; refusing it names the verb that replaces it. Only the mutating
/// verbs are refused: reading the environment with `pip list` is fine.
pub fn refused_command(cmd: &[String]) -> Option<String> {
    if let Some(verb) = python_module_pip_verb(cmd) {
        return PIP_MUTATING_VERBS
            .contains(&verb)
            .then(|| pip_refusal("python -m pip", verb));
    }
    let program = cmd.first()?.rsplit('/').next()?;
    match program {
        "pip" | "pip3" | "easy_install" => {
            let verb = pip_subcommand(cmd, 1);
            // easy_install has no subcommand: installing is all it does.
            (program == "easy_install" || PIP_MUTATING_VERBS.contains(&verb))
                .then(|| pip_refusal(program, verb))
        }
        _ => None,
    }
}

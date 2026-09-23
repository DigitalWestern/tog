//! The Node tailor's `tog run` refusals (`Tailor::refused_command`): an
//! npm-family install over a `node_modules` projection.

/// The npm-family subcommands that write into `node_modules`. `npm run`,
/// `npm test`, `npm ls` and the rest are untouched: only the ones that
/// install are a problem.
const NODE_INSTALL_VERBS: &[&str] = &[
    "install",
    "i",
    "add",
    "ci",
    "uninstall",
    "remove",
    "rm",
    "update",
    "upgrade",
    "link",
    "dedupe",
];

/// The npm-family verbs that install the lockfile rather than change it.
/// The advice differs: the bare `tog` replaces these, not `tog add`.
const NODE_REINSTALL_VERBS: &[&str] = &["install", "i", "ci"];

/// `npm install` succeeds, silently replaces the `node_modules` symlink
/// with a real directory, and the next `tog status` says `missing`, so it
/// is refused with the verb that replaces it. Only the installing verbs
/// are refused: reading the environment with `npm ls` is fine.
pub fn refused_command(cmd: &[String]) -> Option<String> {
    let program = cmd.first()?.rsplit('/').next()?;
    let argument = |index: usize| cmd.get(index).map(String::as_str).unwrap_or_default();
    match program {
        // Bare `yarn` and bare `bun` install; bare `npm` and `pnpm` print
        // help. Everything else needs an installing subcommand.
        "npm" | "pnpm" | "yarn" | "bun" => {
            let verb = argument(1);
            let bare_install = verb.is_empty() && matches!(program, "yarn" | "bun");
            if !bare_install && !NODE_INSTALL_VERBS.contains(&verb) {
                return None;
            }
            let invocation = if verb.is_empty() {
                program.to_string()
            } else {
                format!("{program} {verb}")
            };
            // `install` and `ci` install what the lockfile already says, so
            // what replaces them is the bare `tog`, not `tog add`.
            let advice = if bare_install || NODE_REINSTALL_VERBS.contains(&verb) {
                "'tog' sets node_modules up from the lockfile ('tog --fresh' rebuilds it); to change what is in it, \
                 'tog add <package>', 'tog remove <package>', 'tog update'"
            } else {
                "edit dependencies through tog instead: 'tog add <package>', \
                 'tog remove <package>', 'tog update'; 'tog --fresh' rebuilds node_modules"
            };
            Some(format!(
                "'{invocation}' would replace the node_modules projection with a real directory \
                 and leave the closure stale. {advice}"
            ))
        }
        _ => None,
    }
}

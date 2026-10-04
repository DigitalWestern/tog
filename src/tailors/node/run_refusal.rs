//! The Node tailor's `tog run` refusals (`Tailor::refused_command`): an
//! npm-family install over a `node_modules` projection.

/// One npm-family program's subcommands, split into the ones that write
/// into `node_modules` and the rest. Together they are every subcommand
/// the program has, so an option's *value* is never mistaken for one:
/// `npm --prefix . install` has two bare words before the subcommand, and
/// taking the first would read the directory as the subcommand and let an
/// install through. A value that happens to spell a subcommand
/// (`npm --prefix install run`) is read as one, which fails safe: a
/// harmless command is refused, an install never runs.
struct Manager {
    /// The subcommands that write into `node_modules`. `npm run`,
    /// `npm test`, `npm ls` and the rest are untouched: only the ones that
    /// install are a problem.
    installs: &'static [&'static str],
    /// Every other subcommand, aliases included.
    others: &'static [&'static str],
    /// Whether the program installs when given no subcommand at all.
    bare_installs: bool,
    /// Whether a camelCase word or any prefix only one subcommand starts
    /// with names that subcommand, as npm reads its command line.
    abbreviates: bool,
    /// The subcommands that run another command (`npm exec`, `pnpm dlx`),
    /// which may itself be an install.
    runs: &'static [&'static str],
    /// The subcommands whose remaining words are this program's command
    /// line again (`yarn workspaces foreach -A install`).
    reenters: &'static [&'static str],
    /// The global options that take the next word as their value, so
    /// `yarn --cwd .` is a bare install rather than a script named `.`.
    /// Only a program that installs bare needs them.
    value_options: &'static [&'static str],
}

/// npm's commands and aliases, as `lib/utils/cmd-list.js` lists them.
const NPM: Manager = Manager {
    installs: &[
        "install",
        "i",
        "add",
        "in",
        "ins",
        "inst",
        "insta",
        "instal",
        "isnt",
        "isnta",
        "isntal",
        "isntall",
        "ci",
        "clean-install",
        "ic",
        "install-clean",
        "isntall-clean",
        "install-test",
        "it",
        "install-ci-test",
        "cit",
        "clean-install-test",
        "sit",
        "uninstall",
        "un",
        "unlink",
        "remove",
        "rm",
        "r",
        "update",
        "u",
        "up",
        "upgrade",
        "udpate",
        "link",
        "ln",
        "dedupe",
        "ddp",
        "prune",
    ],
    others: &[
        "access",
        "adduser",
        "add-user",
        "approve-scripts",
        "audit",
        "bugs",
        "issues",
        "cache",
        "completion",
        "config",
        "c",
        "deny-scripts",
        "deprecate",
        "diff",
        "dist-tag",
        "dist-tags",
        "docs",
        "home",
        "doctor",
        "edit",
        "exec",
        "x",
        "explain",
        "why",
        "explore",
        "find-dupes",
        "fund",
        "get",
        "help",
        "hlep",
        "help-search",
        "init",
        "create",
        "innit",
        "install-scripts",
        "ll",
        "la",
        "login",
        "logout",
        "ls",
        "list",
        "org",
        "ogr",
        "outdated",
        "owner",
        "author",
        "pack",
        "ping",
        "pkg",
        "prefix",
        "profile",
        "publish",
        "query",
        "rebuild",
        "rb",
        "repo",
        "restart",
        "root",
        "run",
        "run-script",
        "rum",
        "urn",
        "sbom",
        "search",
        "find",
        "s",
        "se",
        "set",
        "shrinkwrap",
        "stage",
        "star",
        "stars",
        "start",
        "stop",
        "team",
        "test",
        "tst",
        "t",
        "token",
        "trust",
        "undeprecate",
        "unpublish",
        "unstar",
        "version",
        "verison",
        "view",
        "info",
        "show",
        "v",
        "whoami",
    ],
    bare_installs: false,
    abbreviates: true,
    runs: &["exec", "x"],
    reenters: &[],
    value_options: &[],
};

/// pnpm's commands and aliases, as `pnpm --help` lists them. `recursive`
/// (`multi`, `m`) is left out on purpose: it prefixes another command
/// (`pnpm recursive install`), so the scan reads past it to that command.
const PNPM: Manager = Manager {
    installs: &[
        "install",
        "i",
        "add",
        "install-test",
        "it",
        "ci",
        "clean-install",
        "ic",
        "install-clean",
        "update",
        "up",
        "upgrade",
        "remove",
        "uninstall",
        "rm",
        "un",
        "uni",
        "link",
        "ln",
        "unlink",
        "dislink",
        "dedupe",
        "prune",
        "patch-commit",
        "patch-remove",
    ],
    others: &[
        "access",
        "init",
        "outdated",
        "audit",
        "change",
        "version",
        "lane",
        "bugs",
        "issues",
        "list",
        "ls",
        "ll",
        "la",
        "licenses",
        "licences",
        "why",
        "view",
        "info",
        "show",
        "v",
        "sbom",
        "whoami",
        "deprecate",
        "undeprecate",
        "unpublish",
        "star",
        "unstar",
        "stars",
        "dist-tag",
        "dist-tags",
        "ping",
        "doctor",
        "search",
        "s",
        "se",
        "find",
        "rebuild",
        "rb",
        "pack",
        "publish",
        "stage",
        "patch",
        "peers",
        "set-script",
        "ss",
        "test",
        "t",
        "tst",
        "run",
        "run-script",
        "exec",
        "dlx",
        "create",
        "completion",
        "start",
        "stop",
        "restart",
        "find-hash",
        "runtime",
        "rt",
        "env",
        "shim",
        "bin",
        "clean",
        "purge",
        "root",
        "prefix",
        "config",
        "c",
        "get",
        "set",
        "pkg",
        "pack-app",
        "store",
        "server",
        "cache",
        "cat-file",
        "cat-index",
        "ignored-builds",
        "approve-builds",
        "import",
        "deploy",
        "fetch",
        "docs",
        "home",
        "repo",
        "self-update",
        "setup",
        "login",
        "adduser",
        "team",
        "owner",
        "owners",
        "logout",
        "with",
        "edit",
        "profile",
        "token",
        "xmas",
        "help",
    ],
    bare_installs: false,
    abbreviates: false,
    runs: &["exec", "dlx"],
    reenters: &["with"],
    value_options: &[],
};

/// yarn's commands, classic (`yarn help`) and berry. `workspace` is left
/// out on purpose: it prefixes a workspace name and another command
/// (`yarn workspace web add x`), so the scan reads past both to that
/// command. `focus` is berry's `yarn workspaces focus`, an install.
const YARN: Manager = Manager {
    installs: &[
        "install",
        "add",
        "remove",
        "upgrade",
        "upgrade-interactive",
        "up",
        "link",
        "unlink",
        "dedupe",
        "unplug",
        "focus",
    ],
    others: &[
        "access",
        "audit",
        "autoclean",
        "bin",
        "cache",
        "check",
        "config",
        "constraints",
        "create",
        "dlx",
        "exec",
        "explain",
        "generate-lock-entry",
        "global",
        "help",
        "import",
        "info",
        "init",
        "licenses",
        "list",
        "login",
        "logout",
        "node",
        "npm",
        "outdated",
        "owner",
        "pack",
        "patch",
        "patch-commit",
        "plugin",
        "policies",
        "publish",
        "rebuild",
        "run",
        "search",
        "set",
        "stage",
        "tag",
        "team",
        "test",
        "version",
        "versions",
        "why",
        "workspaces",
    ],
    bare_installs: true,
    abbreviates: false,
    runs: &["exec", "dlx"],
    reenters: &["workspaces"],
    value_options: &[
        "--cwd",
        "--use-yarnrc",
        "--link-folder",
        "--global-folder",
        "--modules-folder",
        "--preferred-cache-folder",
        "--cache-folder",
        "--mutex",
        "--emoji",
        "--proxy",
        "--https-proxy",
        "--registry",
        "--network-concurrency",
        "--network-timeout",
        "--scripts-prepend-node-path",
        "--otp",
        "--prod",
        "--production",
    ],
};

/// bun's commands and aliases, as `bun --help` lists them. `bun upgrade`
/// upgrades bun itself; `bun update` is the one that installs. A bare
/// `bun` prints its help.
const BUN: Manager = Manager {
    installs: &[
        "install", "i", "add", "a", "remove", "rm", "update", "link", "unlink", "dedupe", "prune",
        "patch",
    ],
    others: &[
        "run", "test", "x", "repl", "exec", "audit", "outdated", "publish", "pm", "info", "why",
        "build", "init", "create", "c", "upgrade", "help",
    ],
    bare_installs: false,
    abbreviates: false,
    runs: &["x", "exec"],
    reenters: &[],
    value_options: &[],
};

/// The options that make a bare yarn do something other than install: print its version or help, or evaluate a script.
const NOT_AN_INSTALL: &[&str] = &[
    "-v",
    "--version",
    "--revision",
    "-h",
    "--help",
    "-e",
    "--eval",
    "-p",
    "--print",
];

/// The npm-family verbs that install the lockfile rather than change it.
/// The advice differs: the bare `tog` replaces these, not `tog add`.
const NODE_REINSTALL_VERBS: &[&str] = &[
    "install",
    "i",
    "in",
    "ins",
    "inst",
    "insta",
    "instal",
    "isnt",
    "isnta",
    "isntal",
    "isntall",
    "ci",
    "clean-install",
    "ic",
    "install-clean",
    "isntall-clean",
    "install-test",
    "it",
    "install-ci-test",
    "cit",
    "clean-install-test",
    "sit",
];

/// The programs that only run another command: `npx npm install` is the
/// install it runs.
const RUNNERS: &[&str] = &["npx", "pnpx", "bunx"];

fn manager(program: &str) -> Option<&'static Manager> {
    match program {
        "npm" => Some(&NPM),
        "pnpm" => Some(&PNPM),
        "yarn" => Some(&YARN),
        "bun" => Some(&BUN),
        _ => None,
    }
}

/// The subcommand `word` names, and whether it names it outright rather
/// than by abbreviation. An abbreviating program reads it as npm's `deref`
/// (`lib/utils/cmd-list.js`) does: camelCase as kebab-case (`installTest`
/// is `install-test`), then an exact command or alias, then a prefix that
/// only one command or alias starts with (`dedu`, `upd`).
fn resolve(manager: &Manager, word: &str) -> Option<(&'static str, bool)> {
    let words = || manager.installs.iter().chain(manager.others).copied();
    let kebab: String;
    let word = if manager.abbreviates && word.contains(|c: char| c.is_ascii_uppercase()) {
        kebab = word
            .chars()
            .flat_map(|c| match c.is_ascii_uppercase() {
                true => vec!['-', c.to_ascii_lowercase()],
                false => vec![c],
            })
            .collect();
        &kebab
    } else {
        word
    };
    if let Some(exact) = words().find(|candidate| *candidate == word) {
        return Some((exact, true));
    }
    if !manager.abbreviates || word.is_empty() {
        return None;
    }
    let mut prefixed = words().filter(|candidate| candidate.starts_with(word));
    match (prefixed.next(), prefixed.next()) {
        (Some(only), None) => Some((only, false)),
        _ => None,
    }
}

/// The program's subcommand and its position: the first word that is one,
/// wherever it sits among the global options. A harmless subcommand named
/// only by abbreviation may be an option's value (`npm --prefix doc
/// install`), so the scan reads on past it for one named outright or for
/// an install.
fn subcommand(manager: &Manager, cmd: &[String]) -> Option<(&'static str, usize)> {
    let mut abbreviated = None;
    for (index, word) in cmd.iter().enumerate().skip(1) {
        let Some((verb, exact)) = resolve(manager, word) else {
            continue;
        };
        if exact || manager.installs.contains(&verb) {
            return Some((verb, index));
        }
        abbreviated.get_or_insert((verb, index));
    }
    abbreviated
}

/// The install inside a command another one runs (`npm exec -- npm
/// install`, `npx yarn add x`, `pnpm dlx npm ci`): the first word naming an
/// npm-family program starts it, and a word holding spaces is a shell
/// command line of its own (`npm exec -c 'npm install'`).
fn nested(words: &[String]) -> Option<String> {
    for (index, word) in words.iter().enumerate() {
        if word.contains(char::is_whitespace) {
            let line: Vec<String> = word.split_whitespace().map(str::to_string).collect();
            if let Some(refusal) = nested(&line) {
                return Some(refusal);
            }
            continue;
        }
        let program = word.rsplit('/').next().unwrap_or(word);
        if manager(program).is_some() || RUNNERS.contains(&program) {
            if let Some(refusal) = refused_command(&words[index..]) {
                return Some(refusal);
            }
        }
    }
    None
}

/// With no subcommand, yarn and bun install unless asked about themselves
/// or given a script or file to run (`yarn build`, `bun index.ts`): a bare
/// word that is not an option's value is one of those.
fn bare_install(manager: &Manager, cmd: &[String]) -> bool {
    if !manager.bare_installs {
        return false;
    }
    let mut words = cmd.iter().skip(1).map(String::as_str);
    while let Some(word) = words.next() {
        let (option, inline_value) = match word.split_once('=') {
            Some((option, _)) => (option, true),
            None => (word, false),
        };
        if NOT_AN_INSTALL.contains(&option) || !word.starts_with('-') {
            return false;
        }
        if !inline_value && manager.value_options.contains(&word) {
            words.next();
        }
    }
    true
}

/// `npm install` succeeds, silently replaces the `node_modules` symlink
/// with a real directory, and the next `tog status` says `missing`, so it
/// is refused with the verb that replaces it. Only the installing verbs
/// are refused: reading the environment with `npm ls` is fine.
pub fn refused_command(cmd: &[String]) -> Option<String> {
    let program = cmd.first()?.rsplit('/').next()?;
    if RUNNERS.contains(&program) {
        return nested(&cmd[1..]);
    }
    let manager = manager(program)?;
    let verb = match subcommand(manager, cmd) {
        Some((verb, _)) if manager.installs.contains(&verb) => verb,
        Some((verb, index)) if manager.runs.contains(&verb) => return nested(&cmd[index + 1..]),
        Some((verb, index)) if manager.reenters.contains(&verb) => {
            let again: Vec<String> = std::iter::once(cmd[0].clone())
                .chain(cmd[index + 1..].iter().cloned())
                .collect();
            return match subcommand(manager, &again) {
                Some(_) => refused_command(&again),
                None => None,
            };
        }
        Some(_) => return None,
        // Bare `yarn` installs; bare `npm`, `pnpm` and `bun` print help.
        None if bare_install(manager, cmd) => "",
        None => return None,
    };
    let invocation = if verb.is_empty() {
        program.to_string()
    } else {
        format!("{program} {verb}")
    };
    // `install` and `ci` install what the lockfile already says, so what
    // replaces them is the bare `tog`, not `tog add`.
    let advice = if verb.is_empty() || NODE_REINSTALL_VERBS.contains(&verb) {
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

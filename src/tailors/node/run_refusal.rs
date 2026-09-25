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
    value_options: &[],
};

/// yarn's commands, classic (`yarn help`) and berry. `workspace` is left
/// out on purpose: it prefixes a workspace name and another command
/// (`yarn workspace web add x`), so the scan reads past both to that
/// command.
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
/// upgrades bun itself; `bun update` is the one that installs.
const BUN: Manager = Manager {
    installs: &[
        "install", "i", "add", "a", "remove", "rm", "update", "link", "unlink", "dedupe", "prune",
        "patch",
    ],
    others: &[
        "run", "test", "x", "repl", "exec", "audit", "outdated", "publish", "pm", "info", "why",
        "build", "init", "create", "c", "upgrade", "help",
    ],
    bare_installs: true,
    value_options: &[
        "--cwd",
        "-c",
        "--config",
        "-F",
        "--filter",
        "--elide-lines",
        "--shell",
        "-r",
        "--preload",
        "--require",
        "--import",
        "--env-file",
        "--tsconfig-override",
    ],
};

/// The options that make a bare yarn or bun do something other than
/// install: print its version or help, or evaluate a script.
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

fn manager(program: &str) -> Option<&'static Manager> {
    match program {
        "npm" => Some(&NPM),
        "pnpm" => Some(&PNPM),
        "yarn" => Some(&YARN),
        "bun" => Some(&BUN),
        _ => None,
    }
}

/// The program's subcommand: the first word that is one, wherever it sits
/// among the global options.
fn subcommand<'a>(manager: &Manager, cmd: &'a [String]) -> Option<&'a str> {
    cmd.iter()
        .skip(1)
        .map(String::as_str)
        .find(|word| manager.installs.contains(word) || manager.others.contains(word))
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
    let manager = manager(program)?;
    let verb = match subcommand(manager, cmd) {
        Some(verb) if manager.installs.contains(&verb) => verb,
        Some(_) => return None,
        // Bare `yarn` and bare `bun` install; bare `npm` and `pnpm` print
        // help.
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

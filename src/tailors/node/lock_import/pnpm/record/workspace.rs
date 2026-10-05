//! The workspace members `pnpm-workspace.yaml` names (node tailor), for the
//! freshness check. The file is written by hand and may use any YAML a
//! lock never holds, so only its top-level `packages` list is read, by a
//! reader that leaves the rest of the file alone, and the members are found
//! by pnpm's own glob rules.

use super::*;

/// The directories pnpm's own package search skips (`DEFAULT_IGNORE` in
/// `@pnpm/fs.find-packages`), on top of a workspace's `!` globs.
const PNPM_DEFAULT_IGNORE: [&str; 4] = [
    "**/node_modules/**",
    "**/bower_components/**",
    "**/test/**",
    "**/tests/**",
];

/// The workspace members `pnpm-workspace.yaml` names, the root left out:
/// every directory holding a package.json that one of its `packages` globs
/// matches and no `!` glob, nor pnpm's default ignores, excludes. pnpm
/// applies the `!` globs as an ignore list, so their order does not matter.
/// No workspace file, or one without `packages`, is a single project.
/// `None` when `packages` is in a shape [`workspace_packages`] does not
/// read: the caller skips the member check rather than guess.
pub(crate) fn pnpm_workspace_members(project: &ProjectRoot) -> io::Result<Option<Vec<String>>> {
    const FILE: &str = "pnpm-workspace.yaml";
    let Some(text) = project.read_input_string(Path::new(FILE))? else {
        return Ok(Some(Vec::new()));
    };
    let Some(packages) = workspace_packages(&text) else {
        return Ok(None);
    };
    let (mut include, mut exclude) = (Vec::new(), PNPM_DEFAULT_IGNORE.map(String::from).to_vec());
    for raw in &packages {
        let negated = raw.starts_with('!');
        let pattern = raw.trim_start_matches('!').trim_start_matches("./");
        if pattern.starts_with('/') || pattern.split('/').any(|part| part == "..") {
            return Err(err(format!(
                "{FILE}: packages pattern {raw:?} escapes the project"
            )));
        }
        if negated { &mut exclude } else { &mut include }.push(pattern.to_string());
    }
    let mut members = Vec::new();
    collect_members(project, Path::new("."), &include, &exclude, &mut members)?;
    members.sort();
    members.dedup();
    Ok(Some(members))
}

/// The top-level `packages` list of a pnpm-workspace.yaml, read without
/// parsing the rest of the file: a block list at any one indentation (none
/// included) or a flow list, possibly over several lines, of plain or
/// quoted scalars. Empty when there is no such key. `None` when the value
/// is anything else (an anchor, an alias, a block scalar, a mapping item, a
/// scalar continued on the next line).
fn workspace_packages(text: &str) -> Option<Vec<String>> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut lines = text
        .lines()
        .map(|line| line.strip_suffix('\r').unwrap_or(line));
    let value = loop {
        let Some(line) = lines.next() else {
            return Some(Vec::new());
        };
        if let Some(rest) = top_level_value(line, "packages") {
            break strip_yaml_comment(rest).trim();
        }
    };
    if value.starts_with('[') {
        let mut flow = value.to_string();
        while !flow.ends_with(']') {
            flow.push(' ');
            flow.push_str(strip_yaml_comment(lines.next()?).trim());
        }
        let inner = &flow[1..flow.len() - 1];
        return split_top_level(inner, ',')
            .iter()
            .map(|item| item.trim())
            .filter(|item| !item.is_empty())
            .map(workspace_scalar)
            .collect();
    }
    if !value.is_empty() {
        return None;
    }
    let (mut items, mut indent) = (Vec::new(), None);
    for line in lines {
        let content = strip_yaml_comment(line);
        if content.trim().is_empty() {
            continue;
        }
        if line.starts_with("---") || line.starts_with("...") {
            break;
        }
        let depth = content.len() - content.trim_start_matches(' ').len();
        let item = content[depth..]
            .strip_prefix('-')
            .filter(|rest| rest.is_empty() || rest.starts_with([' ', '\t']));
        match item {
            Some(item) if indent.is_none_or(|indent| indent == depth) => {
                indent = Some(depth);
                items.push(workspace_scalar(item.trim())?);
            }
            // The next top-level key ends the list.
            None if depth == 0 => break,
            _ => return None,
        }
    }
    Some(items)
}

/// What follows `key:` when `line` starts that key at the top level, plain
/// or quoted.
fn top_level_value<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    ["", "'", "\""].into_iter().find_map(|quote| {
        let rest = line.strip_prefix(quote)?.strip_prefix(key)?;
        let rest = rest.strip_prefix(quote)?.trim_start_matches([' ', '\t']);
        let rest = rest.strip_prefix(':')?;
        (rest.is_empty() || rest.starts_with([' ', '\t'])).then_some(rest)
    })
}

/// A list item as a string: a quoted scalar closed on its line, or a plain
/// one that opens no other YAML node. A plain `!x` is kept as text, as a
/// negated pattern.
fn workspace_scalar(item: &str) -> Option<String> {
    if item.starts_with(['\'', '"']) {
        return (item.len() >= 2 && item.ends_with(&item[..1])).then(|| yaml_unquote(item));
    }
    let opens_node = item.is_empty()
        || item.starts_with(['&', '*', '|', '>', '[', '{', '%', '@', '`', '-'])
        || item.contains(": ")
        || item.ends_with(':');
    (!opens_node).then(|| item.to_string())
}

/// Does `pattern` match `path`, or, with `below`, could it match `path` or
/// a path under it? pnpm globs with `dot: false`: a `*`, `?` or `**` never
/// matches a path segment that starts with `.`, so only a pattern segment
/// that itself starts with `.` reaches one (`packages/**` does not reach
/// `packages/web/.output`).
fn pnpm_glob_matches(pattern: &str, path: &str, below: bool) -> bool {
    fn matches(pattern: &[&str], path: &[&str], below: bool) -> bool {
        let (Some((&first, rest)), Some((&segment, under))) =
            (pattern.split_first(), path.split_first())
        else {
            return if pattern.is_empty() {
                path.is_empty()
            } else {
                below || pattern.iter().all(|part| *part == "**")
            };
        };
        let hidden = segment.starts_with('.') && !first.starts_with('.');
        if first == "**" {
            matches(rest, path, below) || (!hidden && matches(pattern, under, below))
        } else {
            !hidden && workspace_segment_matches(first, segment) && matches(rest, under, below)
        }
    }
    fn segments(text: &str) -> Vec<&str> {
        text.split('/').filter(|part| !part.is_empty()).collect()
    }
    matches(&segments(pattern), &segments(path), below)
}

/// Collect every directory under `directory` (project-relative, `.` for
/// the root) holding a package.json that an `include` glob matches and no
/// `exclude` glob does. Only directories an `include` glob can reach are
/// opened, and one tog may not open (another user's database directory)
/// holds no member, as for pnpm's own search. A symlinked directory is not
/// descended into, and nothing under `node_modules` is a member.
fn collect_members(
    project: &ProjectRoot,
    directory: &Path,
    include: &[String],
    exclude: &[String],
    result: &mut Vec<String>,
) -> io::Result<()> {
    let denied = |error: &io::Error| error.kind() == io::ErrorKind::PermissionDenied;
    let entries = match project.read_input_dir(directory) {
        Ok(Some(entries)) => entries,
        Ok(None) => return Ok(()),
        Err(error) if denied(&error) => return Ok(()),
        Err(error) => return Err(error),
    };
    let any = |patterns: &[String], path: &str, below: bool| {
        patterns
            .iter()
            .any(|pattern| pnpm_glob_matches(pattern, path, below))
    };
    for file_name in entries {
        if file_name == "node_modules" {
            continue;
        }
        let path = if directory == Path::new(".") {
            PathBuf::from(&file_name)
        } else {
            directory.join(&file_name)
        };
        let relative = path.to_string_lossy().into_owned();
        if !any(include, &relative, true) {
            continue;
        }
        match project.entry(&path) {
            Ok(Entry::Directory) => {}
            Ok(_) => continue,
            Err(error) if denied(&error) => continue,
            Err(error) => return Err(error),
        }
        if any(include, &relative, false)
            && !any(exclude, &relative, false)
            && project.is_input_file(&path.join("package.json"))
        {
            result.push(relative);
        }
        collect_members(project, &path, include, exclude, result)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packages(text: &str) -> Option<Vec<String>> {
        workspace_packages(text)
    }

    #[test]
    fn the_packages_list_is_read_in_every_list_form_and_nothing_else_is_parsed() {
        let want = Some(vec!["packages/*".to_string(), "!**/skip".to_string()]);
        for text in [
            "packages:\n- packages/*\n- '!**/skip'\n",
            "packages:\n    - \"packages/*\"   # libraries\n\n    - '!**/skip'\n",
            "---\n# workspace\npackages: [packages/*, '!**/skip']\n",
            "packages: [\n  packages/*,  # libraries\n  \"!**/skip\",\n]\n",
            "'packages':\n  - packages/*\n  - !**/skip\nonlyBuiltDependencies: [\n  esbuild,\n]\n",
            "catalog: &shared\n  react: ^18\n  text: |\n    packages:\n      - nope\noverrides:\n  packages: x\n  b: *shared\npackages:\n  - packages/*\n  - '!**/skip'\ncatalogs:\n   odd:\n         a: 1\n",
        ] {
            assert_eq!(packages(text), want, "{text}");
        }
        assert_eq!(packages("packages: []\n"), Some(Vec::new()));
        assert_eq!(packages("catalog:\n  a: ^1\n"), Some(Vec::new()));
        assert_eq!(packages("packages:\ncatalog: {}\n"), Some(Vec::new()));
        for text in [
            "packages: &list\n  - a\n",
            "packages: *list\n",
            "packages:\n  - a\n   - b\n",
            "packages:\n  - a\n    b\n",
            "packages:\n  - name: a\n",
            "packages:\n  - 'a\n    b'\n",
            "packages: [a,\n",
            "packages: a\n",
        ] {
            assert_eq!(packages(text), None, "{text}");
        }
    }

    #[test]
    fn a_wildcard_never_matches_a_dot_segment() {
        assert!(pnpm_glob_matches("packages/**", "packages/web", false));
        assert!(!pnpm_glob_matches(
            "packages/**",
            "packages/web/.output/server",
            false
        ));
        assert!(!pnpm_glob_matches("**", ".next/standalone", false));
        assert!(!pnpm_glob_matches("packages/*", "packages/.cache", false));
        assert!(!pnpm_glob_matches("packages/?x", "packages/.x", false));
        assert!(pnpm_glob_matches(".hidden/*", ".hidden/a", false));
        assert!(pnpm_glob_matches("packages/.*", "packages/.cache", false));
        assert!(pnpm_glob_matches("packages/*/app", "packages", true));
        assert!(!pnpm_glob_matches("packages/*", "packages/a/b", true));
        assert!(!pnpm_glob_matches("packages/*", "data", true));
    }

    #[test]
    fn the_member_walk_stays_inside_the_globs_and_passes_over_unreadable_directories() {
        use std::os::unix::fs::PermissionsExt;
        let scratch = crate::kernel::testutil::TempDir::named("pnpm-walk");
        let dir = &scratch.0;
        for member in [
            "packages/web",
            "packages/web/.output/server",
            ".next/standalone",
            "packages/secret/inner",
            "data/postgres/inner",
        ] {
            std::fs::create_dir_all(dir.join(member)).unwrap();
            std::fs::write(dir.join(member).join("package.json"), "{}").unwrap();
        }
        std::fs::write(
            dir.join("pnpm-workspace.yaml"),
            "packages:\n- packages/**\n- '*/standalone'\n",
        )
        .unwrap();
        let project = ProjectRoot::open(dir).unwrap();
        let members = || pnpm_workspace_members(&project).unwrap().unwrap();
        assert_eq!(
            members(),
            ["packages/secret/inner", "packages/web"],
            "no dot directory is a member"
        );
        // SAFETY: geteuid has no preconditions.
        if unsafe { libc::geteuid() } == 0 {
            eprintln!("skip unreadable directories: running as root");
            return;
        }
        let locked = [dir.join("data/postgres"), dir.join("packages/secret")];
        for path in &locked {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o000)).unwrap();
        }
        let result = pnpm_workspace_members(&project);
        for path in &locked {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        assert_eq!(result.unwrap().unwrap(), ["packages/web"]);
    }
}

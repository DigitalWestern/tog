//! Where an object's `bin/` links lead (store layer): checked once, at
//! publication, so every object a closure can put on PATH runs only
//! programs inside itself or inside an object it declares (#525).

use super::Store;
use std::collections::{BTreeSet, VecDeque};
use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};

/// The most links one `bin/` entry may pass through, as the kernel's own
/// limit (`MAXSYMLINKS`) is 40.
const MAX_HOPS: usize = 40;

/// Where following a path from the object's root ends.
#[derive(Debug, PartialEq, Eq)]
enum Landing {
    /// Inside the object, on something that exists.
    Inside,
    /// Inside the object, on nothing: it runs nothing.
    Dangling,
    /// Outside the object, at this path (not yet resolved further).
    Outside(PathBuf),
}

/// Refuse publication when an entry of the staged object's top-level
/// `bin/` (or `bin` itself) is a link that leads anywhere but inside the
/// object or inside one of `deps`, the objects it declares. The comforter
/// puts an object's `bin/` on PATH, so a link out of it, to the host or
/// to an object the record does not name, would run a program the
/// object's identity says nothing about. A Python env links `bin/python`
/// into its interpreter object, a declared dependency, and passes. A link
/// that dangles inside the object runs nothing and passes too.
///
/// Links are followed as they will read once published at `dest`, not in
/// the staging directory, since a relative target means what it means
/// from `dest`. A hop that stays inside the object is read from the staged
/// copy, and a path that leaves it is resolved on disk.
pub(super) fn check_bin_links(
    store: &Store,
    id: &str,
    staged: &Path,
    dest: &Path,
    deps: &BTreeSet<String>,
) -> io::Result<()> {
    let bin = OsString::from("bin");
    match follow(staged, dest, std::slice::from_ref(&bin))? {
        Landing::Dangling => return Ok(()),
        Landing::Outside(path) => return admit(store, id, "bin", path, deps),
        Landing::Inside => {}
    }
    // `bin` itself stayed inside: list it where it really is.
    let real_bin = staged.join(
        fs::canonicalize(staged.join("bin"))?
            .strip_prefix(fs::canonicalize(staged)?)
            .map_err(|_| io::Error::other("bin/ resolved outside the staged object"))?,
    );
    let entries = match fs::read_dir(&real_bin) {
        Ok(entries) => entries,
        // A file named `bin` has no entries to put on PATH.
        Err(error) if error.raw_os_error() == Some(libc::ENOTDIR) => return Ok(()),
        Err(error) => return Err(error),
    };
    let mut names: Vec<OsString> = entries
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<io::Result<_>>()?;
    names.sort();
    for name in names {
        let shown = format!("bin/{}", name.to_string_lossy());
        if let Landing::Outside(path) = follow(staged, dest, &[bin.clone(), name])? {
            admit(store, id, &shown, path, deps)?;
        }
    }
    Ok(())
}

/// An entry that left the object is admitted when, resolved on disk, it
/// lands inside a declared dependency object.
fn admit(
    store: &Store,
    id: &str,
    entry: &str,
    path: PathBuf,
    deps: &BTreeSet<String>,
) -> io::Result<()> {
    let refused = |landed: String| {
        let declared = if deps.is_empty() {
            "it declares none".to_string()
        } else {
            deps.iter().cloned().collect::<Vec<_>>().join(", ")
        };
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "object {id}: {entry} leads to {landed}, outside the object and the \
                 objects it declares ({declared}); nothing was published"
            ),
        )
    };
    let real = fs::canonicalize(&path)
        .map_err(|_| refused(format!("{}, which does not exist", path.display())))?;
    for dep in deps {
        if let Ok(object) = fs::canonicalize(store.object_path(dep)) {
            if real.starts_with(&object) {
                return Ok(());
            }
        }
    }
    Err(refused(real.display().to_string()))
}

/// Follow `parts` from the object's root as the kernel would once the
/// object sits at `dest`, reading each link inside it from `staged`. Stops
/// at the first step out of the object, since what lies outside is already
/// on disk and resolves there.
fn follow(staged: &Path, dest: &Path, parts: &[OsString]) -> io::Result<Landing> {
    let mut resolved = dest.to_path_buf();
    let mut remaining: VecDeque<OsString> = parts.iter().cloned().collect();
    let mut hops = 0;
    while let Some(part) = remaining.pop_front() {
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." {
            resolved.pop();
            continue;
        }
        let candidate = resolved.join(&part);
        // An absolute target walks down from `/` through `dest`'s own
        // ancestors on its way back in.
        if candidate != dest && dest.starts_with(&candidate) {
            resolved = candidate;
            continue;
        }
        let Ok(inside) = candidate.strip_prefix(dest) else {
            let mut outside = candidate;
            outside.extend(remaining);
            return Ok(Landing::Outside(outside));
        };
        let at = staged.join(inside);
        match fs::symlink_metadata(&at) {
            Ok(meta) if meta.file_type().is_symlink() => {
                hops += 1;
                if hops > MAX_HOPS {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("{}: more than {MAX_HOPS} links", candidate.display()),
                    ));
                }
                let target = fs::read_link(&at)?;
                if target.is_absolute() {
                    resolved = PathBuf::from("/");
                }
                for component in target.components().rev() {
                    match component {
                        Component::Normal(name) => remaining.push_front(name.to_os_string()),
                        Component::ParentDir => remaining.push_front("..".into()),
                        Component::CurDir | Component::RootDir | Component::Prefix(_) => {}
                    }
                }
            }
            Ok(_) => resolved = candidate,
            Err(_) => return Ok(Landing::Dangling),
        }
    }
    Ok(if resolved.starts_with(dest) {
        Landing::Inside
    } else {
        Landing::Outside(resolved)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn store(label: &str) -> (crate::kernel::testutil::TempDir, Store) {
        let dir = crate::kernel::testutil::TempDir::named(label);
        for sub in ["objects", "meta", "tmp"] {
            fs::create_dir_all(dir.0.join(sub)).unwrap();
        }
        let store = Store::for_test(dir.0.clone());
        (dir, store)
    }

    /// A staged object with `bin/` holding `links`, checked as if it were
    /// published as `objects/self-1` declaring `deps`.
    fn check(store: &Store, links: &[(&str, &Path)], deps: &[&str]) -> io::Result<()> {
        let staged = store.root.join("tmp").join("stage");
        let _ = fs::remove_dir_all(&staged);
        fs::create_dir_all(staged.join("bin")).unwrap();
        fs::create_dir_all(staged.join("lib")).unwrap();
        fs::write(staged.join("lib/tool"), "x").unwrap();
        fs::write(staged.join("bin/real"), "x").unwrap();
        for (name, target) in links {
            symlink(target, staged.join("bin").join(name)).unwrap();
        }
        let deps = deps.iter().map(|dep| dep.to_string()).collect();
        let dest = store.object_path("self-1");
        check_bin_links(store, "self-1", &staged, &dest, &deps)
    }

    #[test]
    fn links_inside_the_object_or_into_a_declared_object_pass() {
        let (_dir, store) = store("bin-links-pass");
        let python = store.object_path("cpython-1");
        fs::create_dir_all(python.join("bin")).unwrap();
        fs::write(python.join("bin/python3.12"), "x").unwrap();
        symlink("python3.12", python.join("bin/python3")).unwrap();
        let own = store.object_path("self-1").join("lib/tool");
        let links: &[(&str, &Path)] = &[
            ("tool", Path::new("../lib/tool")),
            ("alias", Path::new("tool")),
            ("dangling", Path::new("nothing")),
            ("up-and-back", Path::new("../../self-1/bin/real")),
            ("own-absolute", &own),
            ("python", &python.join("bin/python3")),
        ];
        check(&store, links, &["cpython-1"]).unwrap();
    }

    #[test]
    fn links_to_the_host_or_an_undeclared_object_are_refused() {
        let (_dir, store) = store("bin-links-refuse");
        let other = store.object_path("other-1");
        fs::create_dir_all(other.join("bin")).unwrap();
        fs::write(other.join("bin/tool"), "x").unwrap();
        let host = store.root.join("host-tool");
        fs::write(&host, "x").unwrap();
        for (name, target, needle) in [
            ("escape", host.clone(), "host-tool"),
            ("undeclared", other.join("bin/tool"), "other-1"),
            (
                "relative",
                PathBuf::from("../../other-1/bin/tool"),
                "other-1",
            ),
            ("store", PathBuf::from("../.."), "outside the object"),
            ("missing", store.root.join("gone"), "does not exist"),
        ] {
            let error = check(&store, &[(name, &target)], &[]).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{name}");
            let text = error.to_string();
            assert!(text.contains(&format!("bin/{name}")), "{text}");
            assert!(text.contains(needle), "{name}: {text}");
            assert!(text.contains("nothing was published"), "{text}");
        }
        // Through a link inside the object that then leaves it.
        let error = check(
            &store,
            &[("hop", Path::new("../lib/../bin/out")), ("out", &host)],
            &[],
        )
        .unwrap_err();
        assert!(error.to_string().contains("host-tool"), "{error}");
    }

    #[test]
    fn a_bin_that_is_itself_a_link_out_is_refused() {
        let (_dir, store) = store("bin-links-dir");
        let staged = store.root.join("tmp").join("stage");
        fs::create_dir_all(&staged).unwrap();
        symlink("/usr/bin", staged.join("bin")).unwrap();
        let dest = store.object_path("self-1");
        let error =
            check_bin_links(&store, "self-1", &staged, &dest, &BTreeSet::new()).unwrap_err();
        assert!(
            error.to_string().contains("object self-1: bin leads to"),
            "{error}"
        );
        // `bin -> usr/bin` inside the object is listed where it points.
        fs::remove_file(staged.join("bin")).unwrap();
        fs::create_dir_all(staged.join("usr/bin")).unwrap();
        symlink("/etc/passwd", staged.join("usr/bin/passwd")).unwrap();
        symlink("usr/bin", staged.join("bin")).unwrap();
        let error =
            check_bin_links(&store, "self-1", &staged, &dest, &BTreeSet::new()).unwrap_err();
        assert!(error.to_string().contains("bin/passwd"), "{error}");
    }
}

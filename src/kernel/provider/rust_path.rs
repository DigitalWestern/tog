//! A Rust toolchain that is a directory on this machine (kernel provider
//! layer): what `[toolchain] path = "/custom/rust"` in a rustup toolchain
//! file names.
//!
//! rustup runs such a toolchain as it is. tog does the same, with the two
//! things a lock needs added. First, identity: the tree is probed
//! (`bin/rustc -vV`, `bin/cargo -V`) and content-hashed when the lock is
//! written, and the lock's row for it carries `source = "path"`, the
//! `file://` URL of the tree, both version lines, and that hash. Second,
//! the check: every later realization re-probes and re-hashes the tree, and
//! a tree that is no longer the one the lock names is refused (fail closed)
//! until `tog update --toolchain rust` locks the new one.
//!
//! The tree is imported into the store as an ordinary Rust object (a copy,
//! verified against the same hash), so builds, closures and GC treat it
//! like any other toolchain and a later edit to the directory cannot change
//! what a closure already built with. Every realization records the
//! `external-toolchain` exception: the toolchain came from no pinned
//! release, and a policy can deny that.

use crate::kernel::activity::StoreActivity;
use crate::kernel::digest::Digest;
use crate::kernel::platform::Platform;
use crate::kernel::policy::{self, Exception, EXTERNAL_TOOLCHAIN};
use crate::kernel::sandbox::Sandbox;
use crate::kernel::store::{ObjectDeps, Store};
use crate::kernel::toolchain::input::{InputRow, RUST_TOOLCHAIN_PATH};
use crate::kernel::toolchain::{
    is_path_url, qualified, ArtifactRow, ArtifactSpec, Bundle, Component, Selected, Version,
    PATH_SOURCE, PATH_URL_SCHEME,
};
use crate::kernel::types::Identity;
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read};
use std::os::unix::fs::PermissionsExt;
use std::path::{Component as PathPart, Path, PathBuf};

/// The layout recipe of an imported local tree: copied as it is, checked
/// against the locked content hash.
pub const PATH_RECIPE: &str = "rust-path/1";

/// The release key a path section records. Provenance only.
pub const PATH_RELEASE: &str = "path";

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

/// Whether `selected` is a local tree rather than a catalog release.
pub fn is_path(selected: &Selected) -> bool {
    !selected.bundle.artifacts.is_empty()
        && selected
            .bundle
            .artifacts
            .iter()
            .all(|row| is_path_url(&row.url))
}

/// What probing a tree says it is.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Probe {
    /// The numeric rustc release (`1.97.0` for `1.97.0-nightly`), the
    /// version the lock and the object are named by.
    version: String,
    /// cargo's numeric release.
    cargo_version: String,
    /// The first lines of `rustc -vV` and `cargo -V`, joined: the build the
    /// lock records and a re-probe must reproduce.
    build: String,
}

/// Run one of the tree's own binaries for its version output, in the build
/// sandbox: the tree read-only, a scratch directory as the only writable
/// place (its home, temp and working directory), no network and a scrubbed
/// environment. The answer is written to a file in the scratch directory,
/// which is read back once the child exits. This touches no store, so it
/// needs no store lease and runs the same while a lock is being written as
/// during a sync.
fn version_output(platform: Platform, tree: &Path, binary: &str, flag: &str) -> io::Result<String> {
    let scratch = std::env::temp_dir().join(format!(
        "tog-rust-path-probe-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_nanos())
    ));
    fs::create_dir_all(&scratch)?;
    let answer = scratch.join("version.txt");
    let program = tree.join("bin").join(binary);
    let (program_arg, answer_arg) = (program.display().to_string(), answer.display().to_string());
    let sandbox = Sandbox {
        read: vec![tree],
        write: Vec::new(),
    };
    let ran = sandbox.run_in_on(
        platform,
        &[
            "/bin/sh",
            "-c",
            "exec \"$0\" \"$1\" > \"$2\"",
            &program_arg,
            flag,
            &answer_arg,
        ],
        "/usr/bin:/bin",
        &scratch,
        &scratch,
        &[],
    );
    let read = ran.and_then(|()| fs::read(&answer));
    let _ = fs::remove_dir_all(&scratch);
    let bytes = read.map_err(|error| {
        io::Error::new(
            error.kind(),
            format!(
                "the Rust toolchain at {}: bin/{binary} {flag}: {error}",
                tree.display()
            ),
        )
    })?;
    String::from_utf8(bytes).map_err(|_| {
        invalid(format!(
            "the Rust toolchain at {}: bin/{binary} {flag} printed non-UTF-8 output",
            tree.display()
        ))
    })
}

/// The numeric part of a release string (`1.97.0-nightly` -> `1.97.0`),
/// which must be a version tog can compare.
fn numeric_release(tree: &Path, what: &str, release: &str) -> io::Result<String> {
    let numeric = release.split(['-', '+']).next().unwrap_or_default();
    Version::parse(numeric).map_err(|_| {
        invalid(format!(
            "the Rust toolchain at {}: {what} reports release {release:?}, which is not a version",
            tree.display()
        ))
    })?;
    Ok(numeric.to_string())
}

fn probe(tree: &Path, platform: Platform) -> io::Result<Probe> {
    let rustc = version_output(platform, tree, "rustc", "-vV")?;
    let field = |name: &str| {
        rustc
            .lines()
            .find_map(|line| line.strip_prefix(&format!("{name}: ")))
            .map(str::trim)
    };
    let rustc_line = rustc.lines().next().unwrap_or_default().trim().to_string();
    let (Some(release), Some(host)) = (field("release"), field("host")) else {
        return Err(invalid(format!(
            "the Rust toolchain at {}: bin/rustc -vV names no release and host; is it rustc?",
            tree.display()
        )));
    };
    if host != platform.triple() {
        return Err(invalid(format!(
            "the Rust toolchain at {} is built for {host}, not this host ({})",
            tree.display(),
            platform.triple()
        )));
    }
    let version = numeric_release(tree, "bin/rustc -vV", release)?;
    let cargo = version_output(platform, tree, "cargo", "-V")?;
    let cargo_line = cargo.lines().next().unwrap_or_default().trim().to_string();
    let cargo_release = cargo_line
        .strip_prefix("cargo ")
        .and_then(|rest| rest.split_whitespace().next())
        .ok_or_else(|| {
            invalid(format!(
                "the Rust toolchain at {}: bin/cargo -V printed {cargo_line:?}; is it cargo?",
                tree.display()
            ))
        })?;
    let cargo_version = numeric_release(tree, "bin/cargo -V", cargo_release)?;
    Ok(Probe {
        version,
        cargo_version,
        build: format!("{rustc_line}; {cargo_line}"),
    })
}

/// A symlink target inside the tree: relative, and never above the root
/// once resolved against the link's own directory. Anything else would
/// make the imported object depend on a path outside itself.
fn contained_link(relative: &Path, target: &Path) -> bool {
    if target.is_absolute() {
        return false;
    }
    let mut depth: i64 = relative.components().count() as i64 - 1;
    for part in target.components() {
        match part {
            PathPart::Normal(_) => depth += 1,
            PathPart::ParentDir => {
                depth -= 1;
                if depth < 0 {
                    return false;
                }
            }
            PathPart::CurDir => {}
            _ => return false,
        }
    }
    true
}

/// One entry of a tree walk, in a canonical order.
enum Entry {
    Dir,
    File { executable: bool },
    Link(PathBuf),
}

/// Walk `root` in byte order of names, calling `visit` with each entry's
/// path relative to `root`. Symlinks are not followed. A special file
/// (socket, device, fifo) or a symlink that leaves the tree is refused.
fn walk(
    root: &Path,
    relative: &Path,
    visit: &mut dyn FnMut(&Path, &Entry) -> io::Result<()>,
) -> io::Result<()> {
    let mut names: Vec<_> = fs::read_dir(root.join(relative))?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<io::Result<_>>()?;
    names.sort_by(|a, b| a.as_encoded_bytes().cmp(b.as_encoded_bytes()));
    for name in names {
        let path = relative.join(&name);
        let full = root.join(&path);
        let metadata = fs::symlink_metadata(&full)?;
        let kind = metadata.file_type();
        if kind.is_symlink() {
            let target = fs::read_link(&full)?;
            if !contained_link(&path, &target) {
                return Err(invalid(format!(
                    "the Rust toolchain at {}: {} links to {}, outside the toolchain; tog imports only a self-contained tree",
                    root.display(),
                    path.display(),
                    target.display()
                )));
            }
            visit(&path, &Entry::Link(target))?;
        } else if kind.is_dir() {
            visit(&path, &Entry::Dir)?;
            walk(root, &path, visit)?;
        } else if kind.is_file() {
            let executable = metadata.permissions().mode() & 0o111 != 0;
            visit(&path, &Entry::File { executable })?;
        } else {
            return Err(invalid(format!(
                "the Rust toolchain at {}: {} is not a file, directory or symlink",
                root.display(),
                path.display()
            )));
        }
    }
    Ok(())
}

fn file_sha256(path: &Path) -> io::Result<String> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1 << 16];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// The content hash of the tree at `root`: sha256 over one length-prefixed
/// record per entry, in walk order, naming its relative path and kind, a
/// file's executable bit and content sha256, and a link's target. Two trees
/// hash alike exactly when they hold the same names, bytes, links and
/// executable bits. Owners, times and other mode bits are not content.
pub fn tree_digest(root: &Path) -> io::Result<Digest> {
    let mut hasher = Sha256::new();
    let mut record = |fields: &[&[u8]]| {
        for field in fields {
            hasher.update(field.len().to_string().as_bytes());
            hasher.update(b":");
            hasher.update(field);
        }
    };
    record(&[b"rust-path-tree", b"1"]);
    walk(root, Path::new(""), &mut |path, entry| {
        let name = path.as_os_str().as_encoded_bytes();
        match entry {
            Entry::Dir => record(&[b"dir", name]),
            Entry::File { executable } => {
                let sha = file_sha256(&root.join(path))?;
                let mode: &[u8] = if *executable { b"x" } else { b"-" };
                record(&[b"file", name, mode, sha.as_bytes()]);
            }
            Entry::Link(target) => record(&[b"link", name, target.as_os_str().as_encoded_bytes()]),
        }
        Ok(())
    })?;
    Digest::sha256(&hex::encode(hasher.finalize()))
}

/// Copy the tree at `from` into the existing empty directory `to`: files
/// with their bytes and executable bit, directories, and (contained)
/// symlinks as links.
fn copy_tree(from: &Path, to: &Path) -> io::Result<()> {
    walk(from, Path::new(""), &mut |path, entry| {
        let dest = to.join(path);
        match entry {
            Entry::Dir => fs::create_dir(&dest),
            Entry::File { executable } => {
                fs::copy(from.join(path), &dest)?;
                let mode = if *executable { 0o755 } else { 0o644 };
                fs::set_permissions(&dest, fs::Permissions::from_mode(mode))
            }
            Entry::Link(target) => std::os::unix::fs::symlink(target, &dest),
        }
    })
}

/// The directory a `toolchain.path` value names: as written when absolute,
/// against the project directory (where the toolchain file is) when
/// relative, as rustup resolves it. It must exist and be a directory.
fn tree_of(project: &Path, value: &str) -> io::Result<PathBuf> {
    let written = Path::new(value);
    let joined = if written.is_absolute() {
        written.to_path_buf()
    } else {
        project.join(written)
    };
    let tree = joined.canonicalize().map_err(|error| {
        io::Error::new(
            error.kind(),
            format!(
                "rust-toolchain.toml: toolchain.path {value} ({}): {error}",
                joined.display()
            ),
        )
    })?;
    if !tree.is_dir() {
        return Err(invalid(format!(
            "rust-toolchain.toml: toolchain.path {value} ({}) is not a directory",
            tree.display()
        )));
    }
    Ok(tree)
}

/// The bundle a lock records for the local tree the discovered `rows`
/// name, or `None` when they name none. The tree is probed and hashed now:
/// this is the moment the lock's identity for it is taken.
pub fn select(platform: Platform, project: &Path, rows: &[InputRow]) -> io::Result<Option<Bundle>> {
    let Some(value) = rows
        .iter()
        .find(|row| row.field == RUST_TOOLCHAIN_PATH.1)
        .and_then(|row| row.value.as_deref())
    else {
        return Ok(None);
    };
    let tree = tree_of(project, value)?;
    let probe = probe(&tree, platform)?;
    let digest = tree_digest(&tree)?;
    let url = tree
        .to_str()
        .map(|path| format!("{PATH_URL_SCHEME}{path}"))
        .ok_or_else(|| {
            invalid(format!(
                "the Rust toolchain path {} is not UTF-8",
                tree.display()
            ))
        })?;
    Ok(Some(Bundle {
        release: PATH_RELEASE.to_string(),
        revision: None,
        primary: vec!["rustc".into()],
        components: vec![
            Component::new("rustc", &probe.version),
            Component::embedded("cargo", &probe.cargo_version, "rustc"),
        ],
        artifacts: vec![ArtifactRow::new(
            platform,
            "rustc",
            PATH_SOURCE,
            &probe.build,
            PATH_RECIPE,
            &url,
            digest,
        )],
    }))
}

/// The locked row of a path selection, checked before anything is read.
fn locked_row(platform: Platform, selected: &Selected) -> io::Result<(ArtifactSpec, PathBuf)> {
    let row = selected.artifact(platform, "rustc")?;
    if row.recipe != PATH_RECIPE {
        return Err(invalid(format!(
            "cargo: recipe {} in tog-toolchain.toml is not known to this tog; upgrade tog",
            row.recipe
        )));
    }
    if row.digest.algo() != "sha256" {
        return Err(invalid(format!(
            "cargo: the local Rust toolchain row is a {} digest; this tog hashes trees with sha256",
            row.digest.algo()
        )));
    }
    let tree = row
        .url
        .strip_prefix(PATH_URL_SCHEME)
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .ok_or_else(|| {
            invalid(format!(
                "cargo: the local Rust toolchain row names {}, not an absolute file:// path",
                row.url
            ))
        })?;
    Ok((row, tree))
}

/// The object a path selection is imported as, from the locked row alone:
/// no probe, no hash, so an id can be named without touching the tree.
pub fn identity(platform: Platform, selected: &Selected) -> io::Result<Identity> {
    let (row, _) = locked_row(platform, selected)?;
    Ok(Identity {
        kind: "rust".into(),
        name: "rust".into(),
        version: row.version.clone(),
        inputs: BTreeMap::from([
            ("schema".to_string(), PATH_RECIPE.to_string()),
            ("platform".to_string(), platform.triple().to_string()),
            ("tree_sha256".to_string(), row.digest.hex().to_string()),
            ("build".to_string(), row.build.clone()),
        ]),
    })
}

/// Refuse a tree that is no longer the one `row` locked: another build, or
/// other content. This is what makes a path toolchain fail closed.
fn verify(platform: Platform, tree: &Path, row: &ArtifactSpec) -> io::Result<()> {
    let changed = |what: String| {
        invalid(format!(
            "the Rust toolchain at {} changed since tog-toolchain.toml locked it ({what}); \
             run `tog update --toolchain rust` to lock the tree as it is now",
            tree.display()
        ))
    };
    let probe = probe(tree, platform)?;
    if probe.build != row.build || probe.version != row.version {
        return Err(changed(format!(
            "locked {}, now {}",
            row.build, probe.build
        )));
    }
    let digest = tree_digest(tree)?;
    if digest != row.digest {
        return Err(changed(format!(
            "locked content {}, now {}",
            qualified(&row.digest),
            qualified(&digest)
        )));
    }
    Ok(())
}

/// The exception every use of a local tree records.
fn exception(tree: &Path, row: &ArtifactSpec) -> Exception {
    Exception {
        kind: EXTERNAL_TOOLCHAIN.to_string(),
        subject: tree.display().to_string(),
        detail: format!(
            "{} from a local directory (content {}), not a pinned release",
            row.build,
            qualified(&row.digest)
        ),
    }
}

/// Realize a path selection: verify the tree is still the locked one,
/// then import it (or find the import already in the store). The
/// `external-toolchain` exception is recorded either way, before anything
/// is copied, so a policy that denies it stops here.
pub fn realize(
    store: &Store,
    activity: &StoreActivity,
    platform: Platform,
    selected: &Selected,
) -> io::Result<PathBuf> {
    crate::kernel::platform::require_host(platform, "Rust toolchain")?;
    let (row, tree) = locked_row(platform, selected)?;
    verify(platform, &tree, &row)?;
    let identity = identity(platform, selected)?;
    let id = identity.object_id();
    if store.has_with_activity(activity, &id)? {
        // The import carries the exception in its metadata: the cached
        // check records it again, or refuses it under a denying policy.
        policy::check_cached_with_activity(store, activity, &id)?;
        return Ok(store.object_path(&id));
    }
    let exception = exception(&tree, &row);
    policy::record(&exception.kind, &exception.subject, &exception.detail)?;
    let staged = store.stage_with_activity(activity)?;
    let imported = copy_tree(&tree, &staged).and_then(|()| {
        // The copy is what is committed, so it is what must hash to the
        // lock: a tree edited between the check and the copy is refused.
        let copied = tree_digest(&staged)?;
        if copied != row.digest {
            return Err(invalid(format!(
                "the Rust toolchain at {} changed while it was imported (locked content {}, copied {}); run tog again",
                tree.display(),
                qualified(&row.digest),
                qualified(&copied)
            )));
        }
        super::rust::validate_rust_layout(&staged, platform)
    });
    if let Err(error) = imported {
        let _ = crate::kernel::store::remove_tree(&staged);
        return Err(error);
    }
    let candidate = [exception];
    let (path, applied) = store
        .commit_with_activity_and_deps(activity, &identity, &staged, &candidate, &ObjectDeps::new())
        .map_err(|e| io::Error::new(e.kind(), format!("commit the local Rust toolchain: {e}")))?;
    for other in applied {
        if !candidate.contains(&other) {
            policy::record(&other.kind, &other.subject, &other.detail)?;
        }
    }
    Ok(path)
}

/// A fake local toolchain for tests: a tree whose `bin/rustc` and
/// `bin/cargo` are shell scripts printing what the real ones print, with
/// the layout a Rust object needs.
#[cfg(test)]
pub(crate) mod fixtures {
    use super::*;

    pub fn fake_toolchain(tree: &Path, platform: Platform, release: &str) {
        fs::create_dir_all(tree.join("bin")).unwrap();
        fs::create_dir_all(tree.join(format!("lib/rustlib/{}/lib", platform.triple()))).unwrap();
        let script = |name: &str, body: String| {
            let path = tree.join("bin").join(name);
            fs::write(&path, format!("#!/bin/sh\n{body}")).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        };
        script(
            "rustc",
            format!(
                "printf 'rustc {release} (0123abcde 2026-06-26)\\nbinary: rustc\\n\
                 commit-hash: 0123abcde\\nhost: {}\\nrelease: {release}\\n'\n",
                platform.triple()
            ),
        );
        script(
            "cargo",
            format!("printf 'cargo {release} (4567fedcb 2026-06-26)\\n'\n"),
        );
        fs::write(
            tree.join(format!("lib/rustlib/{}/lib/libstd.rlib", platform.triple())),
            b"std",
        )
        .unwrap();
        std::os::unix::fs::symlink("rustc", tree.join("bin/rustc-alias")).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::fake_toolchain;
    use super::*;

    fn host() -> Platform {
        Platform::host().unwrap()
    }

    fn temp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "tog-rust-path-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn path_row(value: &str) -> InputRow {
        InputRow {
            path: PathBuf::from("rust-toolchain.toml"),
            field: RUST_TOOLCHAIN_PATH.1.to_string(),
            value: Some(value.to_string()),
            absent: false,
            sha256: Some("0".repeat(64)),
        }
    }

    #[test]
    fn the_tree_hash_is_content_and_nothing_else() {
        let dir = temp("hash");
        let (a, b) = (dir.join("a"), dir.join("b"));
        fake_toolchain(&a, host(), "1.96.1");
        fake_toolchain(&b, host(), "1.96.1");
        assert_eq!(tree_digest(&a).unwrap(), tree_digest(&b).unwrap());
        // Bytes, an executable bit, a name and a link target each change it.
        let base = tree_digest(&a).unwrap();
        let std = format!("lib/rustlib/{}/lib/libstd.rlib", host().triple());
        fs::write(b.join(&std), b"STD").unwrap();
        assert_ne!(tree_digest(&b).unwrap(), base);
        fs::write(b.join(&std), b"std").unwrap();
        assert_eq!(tree_digest(&b).unwrap(), base);
        fs::set_permissions(b.join(&std), fs::Permissions::from_mode(0o755)).unwrap();
        assert_ne!(tree_digest(&b).unwrap(), base);
        fs::set_permissions(b.join(&std), fs::Permissions::from_mode(0o644)).unwrap();
        fs::remove_file(b.join("bin/rustc-alias")).unwrap();
        std::os::unix::fs::symlink("cargo", b.join("bin/rustc-alias")).unwrap();
        assert_ne!(tree_digest(&b).unwrap(), base);
        // A link out of the tree is refused, not followed.
        fs::remove_file(b.join("bin/rustc-alias")).unwrap();
        std::os::unix::fs::symlink("/usr/bin/env", b.join("bin/rustc-alias")).unwrap();
        let error = tree_digest(&b).unwrap_err();
        assert!(
            error.to_string().contains("outside the toolchain"),
            "{error}"
        );
        assert!(!contained_link(Path::new("bin/x"), Path::new("../../etc")));
        assert!(contained_link(Path::new("bin/x"), Path::new("../lib/y")));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_path_row_selects_the_probed_and_hashed_tree() {
        let dir = temp("select");
        let tree = dir.join("custom-rust");
        fake_toolchain(&tree, host(), "1.97.0-nightly");
        // No path row: the catalog answers.
        assert_eq!(select(host(), &dir, &[]).unwrap(), None);
        // Relative to the project, as rustup reads it.
        let bundle = select(host(), &dir, &[path_row("custom-rust")])
            .unwrap()
            .unwrap();
        assert_eq!(bundle.release, PATH_RELEASE);
        assert_eq!(bundle.component("rustc").unwrap().version, "1.97.0");
        assert_eq!(bundle.component("cargo").unwrap().version, "1.97.0");
        assert!(bundle.complete_for(host()));
        let row = bundle.artifact(host(), "rustc").unwrap();
        assert_eq!(row.recipe, PATH_RECIPE);
        assert_eq!(row.provider, PATH_SOURCE);
        assert_eq!(
            row.url,
            format!("file://{}", tree.canonicalize().unwrap().display())
        );
        assert_eq!(row.digest, tree_digest(&tree).unwrap());
        assert_eq!(
            row.build,
            "rustc 1.97.0-nightly (0123abcde 2026-06-26); cargo 1.97.0-nightly (4567fedcb 2026-06-26)"
        );
        // The same tree named absolutely is the same bundle.
        let absolute = select(host(), &dir, &[path_row(tree.to_str().unwrap())])
            .unwrap()
            .unwrap();
        assert_eq!(absolute, bundle);
        // A missing tree, or one built for another host, is refused.
        let error = select(host(), &dir, &[path_row("nowhere")]).unwrap_err();
        assert!(
            error.to_string().contains("toolchain.path nowhere"),
            "{error}"
        );
        let foreign = dir.join("foreign");
        let other = if host() == Platform::X86_64UnknownLinuxGnu {
            Platform::Aarch64AppleDarwin
        } else {
            Platform::X86_64UnknownLinuxGnu
        };
        fake_toolchain(&foreign, other, "1.96.1");
        let error = select(host(), &dir, &[path_row("foreign")]).unwrap_err();
        assert!(error.to_string().contains("not this host"), "{error}");
        let _ = fs::remove_dir_all(&dir);
    }
}

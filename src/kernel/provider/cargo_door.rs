//! Running the store cargo as a resolver: confined through the door, its
//! https traffic intercepted by the proxy session (crates.io through the
//! [`crates_index`](super::crates_index) route, git dependencies through the
//! git row, any other registry as `unattested-index`).
//!
//! Two tailors use it: the Cargo tailor (`tog add`/`remove`/`update`, a
//! missing `Cargo.lock`, `tog attest`) and Python, for the `Cargo.lock` of
//! an sdist's Rust extension. Every cargo resolution goes through here;
//! none falls back to running cargo directly.
//!
//! How cargo is pointed at the session, all with `--config` before the
//! subcommand:
//!
//! - `http.proxy` is the session's forward-proxy URL with the token as its
//!   credentials, and `http.cainfo` the session CA as the sandbox sees it.
//!   cargo's curl adds that CA to its default roots rather than replacing
//!   them, which is harmless here: the sandbox reaches nothing but the
//!   proxy.
//! - The forced settings (`build.rustc` and `build.rustdoc` at the store
//!   Rust, no wrappers, `cargo:token` as the only credential provider for
//!   every registry, `net.git-fetch-with-cli=true`) come from the
//!   forced-settings table, and the door checks they are present.
//! - `CARGO_HOME` is a directory in the run's scratch, so the user's
//!   `~/.cargo` (its config, credentials, and caches) is never read, and
//!   `CARGO_NET_OFFLINE=false` undoes an inherited offline setting.

use super::crates_index;
use crate::kernel::resolve::door::{ConfinedSpec, ReceiptProducer, Target, Wire, Wiring};
use crate::kernel::resolve::session::Intercept;
use crate::kernel::resolve::snapshot::PathGlob;
use crate::kernel::resolve::{DelegateReport, DelegateSpec, ResolutionDoor};
use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};

/// Why cargo runs isolated, for the missing-capability message.
const WHY: &str = "runs the build.rustc and credential-provider programs a project's \
                   .cargo/config.toml names, and fetches crates from the network";

/// cargo's configuration files in a directory it reads them from.
pub const CONFIG_FILES: [&str; 2] = [".cargo/config.toml", ".cargo/config"];

/// Where a confined cargo run's results go.
pub enum CargoPublish<'a> {
    /// The lock root is a project: `outputs` (the lock and manifests) are
    /// published through the transaction, with the receipt the producer
    /// makes.
    Project {
        outputs: Vec<PathBuf>,
        receipt: Option<ReceiptProducer<'a>>,
    },
    /// The lock root is tog's own (an unpacked sdist): accepted `outputs`
    /// are written back into it, and the caller roots the ledger.
    Detached { outputs: Vec<PathBuf> },
}

/// One confined run of the store cargo.
pub struct CargoRun<'a> {
    /// The store Rust toolchain object (`bin/cargo`, `bin/rustc`).
    pub rust_obj: &'a Path,
    /// Where cargo runs: the workspace root, or the unpacked sdist.
    pub lock_root: &'a Path,
    /// The subcommand and its arguments (`--manifest-path` included).
    pub args: &'a [&'a str],
    pub publish: CargoPublish<'a>,
}

/// The store cargo with output captured, in `lock_root`, offline mode off,
/// rustup's toolchain selection removed, and `PATH` naming the store Rust
/// and the system's own tools (the git `net.git-fetch-with-cli` starts).
pub fn cargo_spec(rust_obj: &Path, lock_root: &Path, args: &[&str]) -> DelegateSpec {
    let mut spec = DelegateSpec::new(rust_obj.join("bin/cargo"));
    spec.args(args)
        .lock_root(lock_root)
        .capture()
        .env("CARGO_NET_OFFLINE", "false")
        .env(
            "PATH",
            format!("{}:/usr/bin:/bin", rust_obj.join("bin").display()),
        )
        .env_remove("RUSTUP_HOME")
        .env_remove("RUSTUP_TOOLCHAIN");
    spec
}

/// Every registry name cargo's configuration in `lock_root` defines
/// (`[registries.<name>]`), so each gets the forced credential provider.
/// cargo reads `.cargo/config.toml` (and the older `.cargo/config`) in the
/// directory it runs in and its ancestors; inside the sandbox the lock root
/// is the only one of those that holds the project's files. An unreadable
/// or malformed file is an error: a registry it hides would keep its
/// credential provider.
pub fn configured_registries(lock_root: &Path) -> io::Result<Vec<String>> {
    let mut names = Vec::new();
    for file in CONFIG_FILES {
        let path = lock_root.join(file);
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(io::Error::new(
                    error.kind(),
                    format!("read {}: {error}", path.display()),
                ))
            }
        };
        let value: toml::Table = toml::from_str(&text).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{}: {error}", path.display()),
            )
        })?;
        if let Some(registries) = value.get("registries").and_then(|r| r.as_table()) {
            names.extend(registries.keys().cloned());
        }
    }
    names.sort();
    names.dedup();
    Ok(names)
}

/// The directories outside `lock_root` that cargo reads as `path`
/// dependencies (and `[patch]` or `[replace]` entries), found from every
/// manifest under the lock root and, in turn, from each of theirs: the
/// door snapshots them beside the lock root as read-only inputs, so a
/// workspace that names `../shared` resolves confined. A path that does not
/// exist is left for cargo to report.
pub fn path_dependency_roots(lock_root: &Path) -> io::Result<Vec<PathBuf>> {
    let lock_root = std::fs::canonicalize(lock_root)?;
    let mut manifests = manifests_under(&lock_root)?;
    let mut outside: Vec<PathBuf> = Vec::new();
    while let Some(manifest) = manifests.pop() {
        let Some(dir) = manifest.parent() else {
            continue;
        };
        for path in path_dependencies(&manifest)? {
            let Ok(found) = std::fs::canonicalize(dir.join(&path)) else {
                continue;
            };
            if found.starts_with(&lock_root) || outside.iter().any(|seen| found.starts_with(seen)) {
                continue;
            }
            let nested = found.join("Cargo.toml");
            if nested.is_file() {
                manifests.push(nested);
            }
            outside.push(found);
        }
    }
    outside.sort();
    Ok(outside)
}

/// Every `Cargo.toml` under `root`, skipping hidden directories and
/// cargo's build output, and not following symlinks.
fn manifests_under(root: &Path) -> io::Result<Vec<PathBuf>> {
    const MAX_DEPTH: usize = 12;
    let mut found = Vec::new();
    let mut stack = vec![(root.to_path_buf(), 0)];
    while let Some((dir, depth)) = stack.pop() {
        let manifest = dir.join("Cargo.toml");
        if manifest.is_file() {
            found.push(manifest);
        }
        if depth >= MAX_DEPTH {
            continue;
        }
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let name = entry.file_name();
            let skip = name.to_string_lossy().starts_with('.') || name == "target";
            if !skip && entry.file_type()?.is_dir() {
                stack.push((entry.path(), depth + 1));
            }
        }
    }
    Ok(found)
}

/// The `path` of every dependency-like entry in `manifest`: the
/// dependency tables (also under `target.<cfg>` and `workspace`),
/// `[patch.<source>]`, and `[replace]`. `[lib]` and `[[bin]]` paths name
/// files of the package itself and are not read. A manifest that does not
/// parse is left for cargo to report.
fn path_dependencies(manifest: &Path) -> io::Result<Vec<String>> {
    const TABLES: [&str; 5] = [
        "dependencies",
        "dev-dependencies",
        "build-dependencies",
        "patch",
        "replace",
    ];
    let text = std::fs::read_to_string(manifest)?;
    let Ok(value) = toml::from_str::<toml::Table>(&text) else {
        return Ok(Vec::new());
    };
    let mut paths = Vec::new();
    let mut tables: Vec<&toml::Table> = vec![&value];
    if let Some(workspace) = value.get("workspace").and_then(|w| w.as_table()) {
        tables.push(workspace);
    }
    if let Some(platforms) = value.get("target").and_then(|t| t.as_table()) {
        tables.extend(platforms.values().filter_map(|t| t.as_table()));
    }
    for table in tables {
        for name in TABLES {
            let Some(entries) = table.get(name).and_then(|d| d.as_table()) else {
                continue;
            };
            // `[patch.<source>]` nests one level deeper than the others.
            let mut stack: Vec<&toml::Value> = entries.values().collect();
            while let Some(entry) = stack.pop() {
                let Some(entry) = entry.as_table() else {
                    continue;
                };
                match entry.get("path").and_then(|p| p.as_str()) {
                    Some(path) => paths.push(path.to_string()),
                    None if name == "patch" => stack.extend(entry.values()),
                    None => {}
                }
            }
        }
    }
    Ok(paths)
}

/// The `ConfinedSpec` of `run`, through the process proxy with TLS
/// interception on the crates.io route. Tests replace the route, the
/// proxy, and the permitted set.
pub fn cargo_confined<'a>(
    run: &CargoRun<'a>,
    publish: CargoPublish<'a>,
    registries: &'a [String],
) -> io::Result<ConfinedSpec<'a>> {
    let mut confined = ConfinedSpec::new("cargo", "cargo", WHY);
    confined.forced.rust = Some(run.rust_obj);
    confined.forced.cargo_registries = registries;
    confined.store_reads = vec![run.rust_obj.to_path_buf()];
    confined.extra_roots = path_dependency_roots(run.lock_root)?;
    // cargo's build output is not a resolution input.
    confined.exclude = vec![PathGlob::new("target")?];
    confined.routes = vec![crates_index::route()?];
    confined.intercept = Intercept::Tls;
    confined.wire = Some(Box::new(|wire: &Wire<'_>| wiring(wire)));
    match publish {
        CargoPublish::Project { outputs, receipt } => {
            confined.outputs = outputs;
            confined.target = Target::Project { receipt };
        }
        CargoPublish::Detached { outputs } => {
            confined.outputs = outputs;
            confined.target = Target::Detached;
        }
    }
    Ok(confined)
}

/// `--config` pairs, forced ones included, before the subcommand; a scratch
/// `CARGO_HOME`.
fn wiring(wire: &Wire<'_>) -> io::Result<Wiring> {
    let ca_file = wire.ca_file.ok_or_else(|| {
        io::Error::other("cargo resolves only through TLS interception, which this run lacks")
    })?;
    let config = |key: &str, value: &str| -> [OsString; 2] {
        // TOML strings: the proxy URL and the CA path hold no quote or
        // backslash (a token is hex, the CA path is fixed).
        ["--config".into(), format!("{key}=\"{value}\"").into()]
    };
    let mut args: Vec<OsString> = Vec::new();
    args.extend(config("http.proxy", &wire.address.proxy_url()));
    args.extend(config("http.cainfo", &ca_file.to_string_lossy()));
    args.extend(wire.forced_args.iter().cloned());
    args.extend(wire.args.iter().cloned());
    Ok(Wiring {
        args,
        env: vec![(
            "CARGO_HOME".into(),
            wire.scratch.join("cargo-home").into_os_string(),
        )],
        ..Wiring::default()
    })
}

/// Run the store cargo confined through `door`. A Detached run's ledger
/// ids come back in the report for the caller to root.
pub fn run_cargo(
    door: &mut ResolutionDoor<'_>,
    mut run: CargoRun<'_>,
) -> io::Result<DelegateReport> {
    let publish = std::mem::replace(
        &mut run.publish,
        CargoPublish::Detached {
            outputs: Vec::new(),
        },
    );
    let registries = configured_registries(run.lock_root)?;
    let confined = cargo_confined(&run, publish, &registries)?;
    let spec = cargo_spec(run.rust_obj, run.lock_root, run.args);
    spec.trace();
    door.run_confined(spec, confined).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("store cargo {}: {error}", run.args.join(" ")),
        )
    })
}

/// `run_cargo` that fails on a nonzero exit, naming cargo's own words.
pub fn run_cargo_checked(
    door: &mut ResolutionDoor<'_>,
    run: CargoRun<'_>,
) -> io::Result<DelegateReport> {
    let args = run.args.join(" ");
    let report = run_cargo(door, run)?;
    if !report.status.success() {
        return Err(io::Error::other(format!(
            "store cargo {args} failed: {}",
            String::from_utf8_lossy(&report.stderr).trim()
        )));
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::testutil::TempDir;

    /// Path dependencies outside the lock root are read roots, found
    /// through every manifest under it and transitively through theirs;
    /// paths inside the root, package file paths, and missing paths are
    /// not.
    #[test]
    fn out_of_root_path_dependencies_are_read_roots() {
        let temp = TempDir::named("cargo-path-roots");
        let write = |relative: &str, text: &str| {
            let path = temp.0.join(relative);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, text).unwrap();
        };
        write(
            "ws/Cargo.toml",
            "[workspace]\nmembers = [\"app\"]\n[workspace.dependencies]\n\
             shared = { path = \"../shared\" }\n\
             [patch.crates-io]\nitoa = { path = \"../patched\" }\n",
        );
        write(
            "ws/app/Cargo.toml",
            "[package]\nname = \"app\"\n[lib]\npath = \"../../elsewhere/lib.rs\"\n\
             [dependencies]\ninner = { path = \"../inner\" }\n\
             missing = { path = \"../../nope\" }\n\
             [target.'cfg(unix)'.dev-dependencies]\nunixy = { path = \"../../unixy\" }\n",
        );
        write("ws/inner/Cargo.toml", "[package]\nname = \"inner\"\n");
        write(
            "shared/Cargo.toml",
            "[package]\nname = \"shared\"\n[dependencies]\ndeep = { path = \"../deep\" }\n",
        );
        write("deep/Cargo.toml", "[package]\nname = \"deep\"\n");
        write("patched/Cargo.toml", "[package]\nname = \"itoa\"\n");
        write("unixy/Cargo.toml", "[package]\nname = \"unixy\"\n");
        write("elsewhere/lib.rs", "");
        write(
            "ws/target/debug/Cargo.toml",
            "[dependencies]\nx = { path = \"../../../elsewhere\" }\n",
        );
        let root = temp.0.canonicalize().unwrap();
        let names: Vec<String> = path_dependency_roots(&temp.0.join("ws"))
            .unwrap()
            .iter()
            .map(|path| path.strip_prefix(&root).unwrap().display().to_string())
            .collect();
        assert_eq!(names, vec!["deep", "patched", "shared", "unixy"]);
    }

    #[test]
    fn registries_are_read_from_both_config_spellings() {
        let temp = TempDir::named("cargo-registries");
        assert!(configured_registries(&temp.0).unwrap().is_empty());
        std::fs::create_dir_all(temp.0.join(".cargo")).unwrap();
        std::fs::write(
            temp.0.join(".cargo/config.toml"),
            "[registries.internal]\nindex = \"sparse+https://cargo.internal.test/\"\n\
             [registries.other]\nindex = \"sparse+https://other.test/\"\n",
        )
        .unwrap();
        std::fs::write(
            temp.0.join(".cargo/config"),
            "[registries]\nlegacy = { index = \"https://legacy.test/index\" }\n\
             internal = { index = \"sparse+https://cargo.internal.test/\" }\n",
        )
        .unwrap();
        assert_eq!(
            configured_registries(&temp.0).unwrap(),
            vec!["internal", "legacy", "other"]
        );
        std::fs::write(temp.0.join(".cargo/config"), "[registries\n").unwrap();
        assert!(configured_registries(&temp.0).is_err());
    }
}

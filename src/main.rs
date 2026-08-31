use blanket::{npm, project, pypi, python, store, types};

use std::io;
use std::path::{Path, PathBuf};
use std::process::exit;

const USAGE: &str = "\
blanket — universal realization & environment kernel (python + node)

USAGE:
  blanket sync [--fresh]  realize + project env(s) from lockfiles
                          (--fresh rebuilds the projection, dropping caches)
  blanket plan            print the locked plan(s) as JSON
  blanket run <cmd...>    run a command inside the projected environment(s)
  blanket store path      print the store root

Project inputs (either or both):
  requirements.txt        python deps; ranged files are auto-locked via uv
                          into requirements.lock.txt (hash-pinned)
  .python-version         optional; e.g. 3.12 (default: 3.12)
  package-lock.json       npm lockfile v2/v3 (npm install --package-lock-only)
";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match args.first().map(String::as_str) {
        Some("sync") => run_sync(args.iter().any(|a| a == "--fresh")),
        Some("plan") => run_plan(),
        Some("run") => run_run(&args[1..]),
        Some("store") if args.get(1).map(String::as_str) == Some("path") => {
            store::Store::open().map(|s| println!("{}", s.root.display()))
        }
        _ => {
            eprint!("{USAGE}");
            exit(2);
        }
    }
    .map(|_| 0)
    .unwrap_or_else(|e| {
        eprintln!("blanket: error: {e}");
        1
    });
    exit(code);
}

fn project_dir() -> PathBuf {
    std::env::current_dir().expect("cwd")
}

/// Plan from project inputs. Planning hits PyPI, so successful plans are
/// cached in .blanket/plan.json keyed by a hash of the inputs; an unchanged
/// lock replans offline and instantly.
fn read_plan(dir: &Path) -> io::Result<types::Plan> {
    let req_path = dir.join("requirements.txt");
    let source = std::fs::read_to_string(&req_path).map_err(|e| {
        io::Error::new(e.kind(), format!("{}: {e}", req_path.display()))
    })?;
    let pyver = std::fs::read_to_string(dir.join(".python-version"))
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "3.12".into());
    let pin = python::lookup(&pyver).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("no pinned CPython matching '{pyver}'"),
        )
    })?;

    // Real projects mostly carry ranged requirements, not hash-pinned ones.
    // Resolution is delegated to the ecosystem's own resolver (uv) — blanket
    // owns realization, not solving. The generated requirements.lock.txt is
    // regenerated whenever requirements.txt changes.
    let text = if is_fully_pinned(&source) {
        source
    } else {
        locked_requirements(dir, &source, pin.version)?
    };

    use sha2::{Digest, Sha256};
    // PLANNER_SCHEMA busts stale caches when planner semantics change.
    const PLANNER_SCHEMA: &str = "python-planner/2";
    let input_hash = hex::encode(Sha256::digest(
        format!("{PLANNER_SCHEMA}\x00{}\x00{}", pin.version, text).as_bytes(),
    ));
    let cache_path = dir.join(".blanket/plan.json");
    if let Ok(cached) = std::fs::read_to_string(&cache_path) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&cached) {
            if v["input_hash"] == input_hash.as_str() {
                if let Ok(plan) = serde_json::from_value(v["plan"].clone()) {
                    return Ok(plan);
                }
            }
        }
    }

    let plan = pypi::plan_python(&text, pin.version)?;
    std::fs::create_dir_all(dir.join(".blanket"))?;
    std::fs::write(
        &cache_path,
        serde_json::to_vec_pretty(&serde_json::json!({
            "input_hash": input_hash,
            "plan": plan,
        }))?,
    )?;
    Ok(plan)
}

/// Every non-comment logical line (after backslash continuations) carries a
/// --hash= option. That is the shape `uv pip compile --generate-hashes`
/// emits and the only shape the planner accepts directly.
fn is_fully_pinned(text: &str) -> bool {
    let mut logical = String::new();
    let mut any = false;
    for raw in text.lines().chain(std::iter::once("")) {
        if let Some(stripped) = raw.strip_suffix('\\') {
            logical.push_str(stripped);
            continue;
        }
        logical.push_str(raw);
        let line = logical.trim();
        let line = match line.find(" #") {
            Some(i) => line[..i].trim(),
            None => line,
        };
        if !line.is_empty() && !line.starts_with('#') {
            any = true;
            if !line.contains("--hash=") {
                return false;
            }
        }
        logical.clear();
    }
    any
}

/// Resolve ranged requirements to a hash-pinned lock via uv, cached in
/// requirements.lock.txt and regenerated when requirements.txt changes.
fn locked_requirements(dir: &Path, source: &str, pyver: &str) -> io::Result<String> {
    use sha2::{Digest, Sha256};
    let lock_path = dir.join("requirements.lock.txt");
    let stamp_path = dir.join(".blanket/lock-source.hash");
    let source_hash = hex::encode(Sha256::digest(format!("{pyver}\x00{source}").as_bytes()));
    if let (Ok(stamp), Ok(lock)) = (
        std::fs::read_to_string(&stamp_path),
        std::fs::read_to_string(&lock_path),
    ) {
        if stamp.trim() == source_hash {
            return Ok(lock);
        }
    }
    eprintln!("blanket: requirements.txt is not hash-pinned; resolving with uv...");
    let status = std::process::Command::new("uv")
        .args(["pip", "compile", "requirements.txt", "--generate-hashes", "--quiet"])
        .args(["--python-version", pyver])
        .args(["-o", "requirements.lock.txt"])
        .current_dir(dir)
        .status()
        .map_err(|e| {
            io::Error::new(
                e.kind(),
                "requirements.txt is not hash-pinned and `uv` was not found; \
                 install uv (https://astral.sh/uv) or provide a hash-pinned file",
            )
        })?;
    if !status.success() {
        return Err(io::Error::other("uv pip compile failed"));
    }
    std::fs::create_dir_all(dir.join(".blanket"))?;
    std::fs::write(&stamp_path, &source_hash)?;
    std::fs::read_to_string(&lock_path)
}

fn run_plan() -> io::Result<()> {
    let dir = project_dir();
    ensure_npm_lock(&dir)?;
    let mut any = false;
    if dir.join("requirements.txt").exists() {
        let plan = read_plan(&dir)?;
        println!("{}", serde_json::to_string_pretty(&plan)?);
        any = true;
    }
    if dir.join("package-lock.json").exists() {
        let plan = npm::plan_npm(&std::fs::read_to_string(dir.join("package-lock.json"))?)?;
        let v: Vec<_> = plan
            .packages
            .iter()
            .map(|p| {
                serde_json::json!({"path": p.path, "version": p.version,
                                   "url": p.url, "integrity": p.integrity})
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "ecosystem": "node", "node_version": plan.node_version, "packages": v
            }))?
        );
        any = true;
    }
    if !any {
        return Err(no_inputs());
    }
    Ok(())
}

fn no_inputs() -> io::Error {
    io::Error::new(
        io::ErrorKind::NotFound,
        "nothing to sync here (need requirements.txt and/or package-lock.json)",
    )
}

/// A package.json without a package-lock.json (bun/yarn/pnpm projects):
/// delegate lock generation to npm, mirroring the uv flow for Python.
/// Resolution is the ecosystem's job; realization is blanket's.
fn ensure_npm_lock(dir: &Path) -> io::Result<()> {
    if !dir.join("package.json").exists() || dir.join("package-lock.json").exists() {
        return Ok(());
    }
    for other in ["bun.lock", "bun.lockb", "yarn.lock", "pnpm-lock.yaml"] {
        if dir.join(other).exists() {
            eprintln!(
                "blanket: note: {other} found; generating package-lock.json via npm \
                 (versions resolve fresh — they may differ from {other})"
            );
            break;
        }
    }
    eprintln!("blanket: no package-lock.json; resolving with npm...");
    let status = std::process::Command::new("npm")
        .args(["install", "--package-lock-only", "--ignore-scripts", "--silent"])
        .current_dir(dir)
        .status()
        .map_err(|e| {
            io::Error::new(
                e.kind(),
                "package.json has no package-lock.json and `npm` was not found; \
                 install Node/npm or provide a package-lock.json",
            )
        })?;
    if !status.success() {
        return Err(io::Error::other("npm install --package-lock-only failed"));
    }
    Ok(())
}

fn run_sync(fresh: bool) -> io::Result<()> {
    let dir = project_dir();
    let store = store::Store::open()?;
    ensure_npm_lock(&dir)?;
    let mut any = false;
    if dir.join("requirements.txt").exists() {
        let plan = read_plan(&dir)?;
        let env = project::realize_env(&store, &plan)?;
        project::project_env(&dir, &env, &plan)?;
        eprintln!("synced: .venv -> {}", env.display());
        any = true;
    }
    if dir.join("package-lock.json").exists() {
        let lock = std::fs::read_to_string(dir.join("package-lock.json"))?;
        let mut config = npm::BlanketConfig::default();
        if let Ok(pkg) = std::fs::read_to_string(dir.join("package.json")) {
            npm::check_lock_freshness(&pkg, &lock)?;
            config = npm::parse_blanket_config(&pkg)?;
        }
        let plan = npm::plan_npm(&lock)?;
        let env = npm::realize_node_env(&store, &plan, &config.artifacts)?;
        npm::project_node_env(&dir, &env, &plan, &config.mutable_packages, fresh)?;
        eprintln!("synced: node_modules -> {}", env.display());
        any = true;
    }
    if !any {
        return Err(no_inputs());
    }
    Ok(())
}

fn run_run(cmd: &[String]) -> io::Result<()> {
    if cmd.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "run: no command given"));
    }
    // Walk up from cwd to the nearest projected root, so `blanket run`
    // works from workspace subdirectories like npm run does.
    let cwd = project_dir();
    let dir = cwd
        .ancestors()
        .find(|d| d.join(".venv").exists() || d.join("node_modules").exists())
        .unwrap_or(&cwd)
        .to_path_buf();
    let venv = dir.join(".venv");
    let nm = dir.join("node_modules");
    let mut prefix: Vec<String> = Vec::new();
    let mut command = std::process::Command::new(&cmd[0]);
    command.args(&cmd[1..]);
    if venv.exists() {
        prefix.push(venv.join("bin").to_string_lossy().into_owned());
        command.env("VIRTUAL_ENV", &venv);
        command.env("PYTHONDONTWRITEBYTECODE", "1"); // site-packages is read-only
    }
    if nm.exists() {
        prefix.push(nm.join(".bin").to_string_lossy().into_owned());
        // Node toolchain from the store (cache hit after sync).
        let store = store::Store::open()?;
        let node = npm::ensure_node(&store)?;
        prefix.push(node.join("bin").to_string_lossy().into_owned());
    }
    if prefix.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "no environment projected here; run `blanket sync` first",
        ));
    }
    let path = std::env::var("PATH").unwrap_or_default();
    prefix.push(path);
    use std::os::unix::process::CommandExt;
    let err = command.env("PATH", prefix.join(":")).exec(); // only returns on failure
    Err(err)
}

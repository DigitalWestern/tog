use blanket::{npm, project, pypi, python, store, types};

use std::io;
use std::path::{Path, PathBuf};
use std::process::exit;

const USAGE: &str = "\
blanket — universal realization & environment kernel (python + node)

USAGE:
  blanket sync            realize + project env(s) from lockfiles
  blanket plan            print the locked plan(s) as JSON
  blanket run <cmd...>    run a command inside the projected environment(s)
  blanket store path      print the store root

Project inputs (either or both):
  requirements.txt        hash-pinned python deps (uv pip compile --generate-hashes)
  .python-version         optional; e.g. 3.12 (default: 3.12)
  package-lock.json       npm lockfile v2/v3 (npm install --package-lock-only)
";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match args.first().map(String::as_str) {
        Some("sync") => run_sync(),
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
    let text = std::fs::read_to_string(&req_path).map_err(|e| {
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

fn run_plan() -> io::Result<()> {
    let dir = project_dir();
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

fn run_sync() -> io::Result<()> {
    let dir = project_dir();
    let store = store::Store::open()?;
    let mut any = false;
    if dir.join("requirements.txt").exists() {
        let plan = read_plan(&dir)?;
        let env = project::realize_env(&store, &plan)?;
        project::project_env(&dir, &env, &plan)?;
        eprintln!("synced: .venv -> {}", env.display());
        any = true;
    }
    if dir.join("package-lock.json").exists() {
        let plan = npm::plan_npm(&std::fs::read_to_string(dir.join("package-lock.json"))?)?;
        let env = npm::realize_node_env(&store, &plan)?;
        npm::project_node_env(&dir, &env, &plan)?;
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
    let dir = project_dir();
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

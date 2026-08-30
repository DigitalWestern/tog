use blanket::{project, pypi, python, store, types};

use std::io;
use std::path::{Path, PathBuf};
use std::process::exit;

const USAGE: &str = "\
blanket — universal realization & environment kernel (MVP: python)

USAGE:
  blanket sync            realize + project env from requirements.txt
  blanket plan            print the locked plan as JSON (no side effects)
  blanket run <cmd...>    run a command inside the projected environment
  blanket store path      print the store root

Project inputs:
  requirements.txt        hash-pinned (pip/uv --generate-hashes format)
  .python-version         optional; e.g. 3.12 (default: 3.12)
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
    let input_hash = hex::encode(Sha256::digest(
        format!("{}\x00{}", pin.version, text).as_bytes(),
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
    let plan = read_plan(&project_dir())?;
    println!("{}", serde_json::to_string_pretty(&plan)?);
    Ok(())
}

fn run_sync() -> io::Result<()> {
    let dir = project_dir();
    let plan = read_plan(&dir)?;
    let store = store::Store::open()?;
    let env = project::realize_env(&store, &plan)?;
    project::project_env(&dir, &env, &plan)?;
    eprintln!("synced: .venv -> {}", env.display());
    Ok(())
}

fn run_run(cmd: &[String]) -> io::Result<()> {
    if cmd.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "run: no command given"));
    }
    let dir = project_dir();
    let venv = dir.join(".venv");
    if !venv.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "no .venv projected here; run `blanket sync` first",
        ));
    }
    let bin = venv.join("bin");
    let path = std::env::var("PATH").unwrap_or_default();
    use std::os::unix::process::CommandExt;
    let err = std::process::Command::new(&cmd[0])
        .args(&cmd[1..])
        .env("VIRTUAL_ENV", &venv)
        .env("PATH", format!("{}:{}", bin.display(), path))
        .exec(); // only returns on failure
    Err(err)
}

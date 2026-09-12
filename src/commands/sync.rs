//! `blanket sync`: preflight every detected ecosystem, then plan, realize,
//! and project each one. Needs every tailor's preflight/plan/realize/project.

use crate::comforter;
use crate::commands::shared::{no_inputs, project_dir};
use crate::kernel::context::Context;
use crate::kernel::platform::Platform;
use crate::kernel::policy;
use crate::kernel::store;
use crate::kernel::ui;
use crate::tailors::cargo;
use crate::tailors::cargo::inputs::is_cargo_here;
use crate::tailors::cargo::inputs::load_cargo_inputs;
use crate::tailors::dotnet;
use crate::tailors::elixir;
use crate::tailors::go;
use crate::tailors::go::inputs::load_go_inputs;
use crate::tailors::node;
use crate::tailors::node::inputs::ensure_npm_lock;
use crate::tailors::node::inputs::load_npm_plan;
use crate::tailors::python;
use crate::tailors::python::inputs::has_python_input;
use crate::tailors::python::inputs::read_plan;
use crate::tailors::python::manifest;
use crate::tailors::python::pyselect;
use crate::tailors::ruby;
use std::io;
use std::path::Path;

fn preflight_sync(platform: Platform, dir: &Path) -> io::Result<()> {
    // Syncing ends by registering this project as a GC root. Check that the
    // path can be recorded before realizing or projecting anything: a
    // finished sync that could not register would leave a projected
    // environment nothing protects, and the next sweep would collect it.
    store::Store::check_registrable(dir)?;
    if [
        "package.json",
        "package-lock.json",
        "pnpm-lock.yaml",
        "yarn.lock",
    ]
    .iter()
    .any(|name| dir.join(name).is_file())
    {
        node::preflight(platform)?;
    }
    if has_python_input(dir)? {
        let selection =
            pyselect::select_python_with_inputs(platform, &manifest::python_inputs(dir)?)?;
        python::preflight(platform, selection.pin.version)?;
    }
    if dir.join("go.mod").is_file() {
        go::preflight_platform(platform)?;
    }
    if dir.join("Gemfile").is_file() {
        ruby::preflight_platform(platform)?;
    }
    if dir.join("mix.exs").is_file() {
        elixir::preflight_platform(platform)?;
    }
    if dotnet::has_marker(dir)? {
        dotnet::preflight_platform(platform)?;
    }
    if is_cargo_here(dir) {
        cargo::preflight_platform(platform)?;
    }
    Ok(())
}

pub fn run(ctx: &Context, fresh: bool, strict: bool) -> io::Result<()> {
    let platform = ctx.platform;
    let dir = project_dir();
    policy::init(&dir, strict)?;
    preflight_sync(platform, &dir)?;
    let store = &ctx.store;
    ensure_npm_lock(platform, &dir, &store)?;
    let mut any = false;
    if has_python_input(&dir)? {
        let (plan, selection, inputs) = read_plan(platform, &dir, &store)?;
        let env = comforter::realize_env(&store, platform, &plan)?;
        comforter::project_env_with_inputs(&dir, &env, &plan, &selection, &inputs)?;
        ui::synced(".venv", &env);
        any = true;
    }
    if let Some(plan) = load_npm_plan(platform, &dir)? {
        let mut config = node::BlanketConfig::default();
        if plan.lock_source == "package-lock.json" {
            let lock = std::fs::read_to_string(dir.join("package-lock.json"))?;
            if let Ok(pkg) = std::fs::read_to_string(dir.join("package.json")) {
                node::check_lock_freshness(&pkg, &lock)?;
                config = node::parse_blanket_config(&pkg)?;
            }
        } else if let Ok(pkg) = std::fs::read_to_string(dir.join("package.json")) {
            config = node::parse_blanket_config(&pkg)?;
        }
        let env = node::realize_node_env(&store, platform, &plan, &config.artifacts)?;
        let inputs = comforter::input_records(
            &dir,
            &[dir.join("package.json"), dir.join(&plan.lock_source)],
        )?;
        node::project_node_env_recorded(
            &dir,
            &env,
            platform,
            &plan,
            &config.mutable_packages,
            fresh,
            &inputs,
        )?;
        ui::synced("node_modules", &env);
        any = true;
    }
    if dir.join("go.mod").is_file() {
        let inputs = load_go_inputs(platform, &dir, &store)?;
        let modcache = go::realize_modcache(&store, platform, &inputs.plan, &inputs.go_obj)?;
        go::project_go_env(
            &dir,
            &inputs.go_obj,
            &modcache,
            &inputs.plan,
            &inputs.gosum_sha256,
        )?;
        ui::synced("go modcache", &modcache);
        any = true;
    }
    if dir.join("Gemfile").is_file() {
        let ruby_obj = ruby::ensure_ruby_for(&store, platform)?;
        let (plan, lock_sha256) = ruby::plan_ruby(&store, &dir, &ruby_obj)?;
        let gems = ruby::realize_gems(&store, platform, &plan, &ruby_obj)?;
        ruby::project_ruby_env(&dir, &ruby_obj, &gems, &plan, &lock_sha256)?;
        ui::synced("gems", &gems);
        any = true;
    }
    if dir.join("mix.exs").is_file() {
        let beam = elixir::ensure_beam_for(&store, platform)?;
        let (plan, lock_sha256) = elixir::plan_elixir(&store, &dir, &beam)?;
        let deps = elixir::realize_deps(&store, platform, &plan, &beam)?;
        let projection =
            elixir::project_elixir_env(platform, &dir, &beam, &deps, &plan, &lock_sha256, fresh)?;
        ui::synced("hex deps", &projection);
        any = true;
    }
    if dotnet::has_marker(&dir)? {
        dotnet::preflight(&dir)?;
        let sdk = dotnet::ensure_sdk_for(&store, platform)?;
        let (plan, lock_sha256) = dotnet::plan_dotnet(&store, &dir, &sdk)?;
        let packages = dotnet::realize_packages(&store, platform, &plan, &sdk, &dir)?;
        dotnet::project_dotnet_env(&dir, &sdk, &packages, &plan, &lock_sha256)?;
        ui::synced("nuget packages", &packages);
        any = true;
    }
    if is_cargo_here(&dir) {
        let inputs = load_cargo_inputs(platform, &dir, &store)?;
        let rust_obj = &inputs.rust_obj;
        let vendor_obj = cargo::realize_vendor(&store, &inputs.plan)?;
        if fresh {
            let cargo_home = inputs.root.join(".blanket/cargo-home");
            if std::fs::symlink_metadata(&cargo_home).is_ok() {
                store::remove_tree(&cargo_home)?;
            }
        }
        cargo::project_cargo_env(
            &inputs.root,
            rust_obj,
            &vendor_obj,
            &inputs.plan,
            &inputs.lock_digest,
        )?;
        ui::synced("cargo env", &vendor_obj);
        any = true;
    }
    if !any {
        return Err(no_inputs());
    }
    print_exception_summary(&dir)?;
    Ok(())
}

fn print_exception_summary(project_dir: &Path) -> io::Result<()> {
    let dir = project_dir.join(".blanket/closures");
    let mut total = 0;
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            if !entry.file_name().to_string_lossy().ends_with(".json") {
                continue;
            }
            let text = match std::fs::read_to_string(entry.path()) {
                Ok(text) => text,
                Err(_) => continue,
            };
            let value: serde_json::Value = match serde_json::from_str(&text) {
                Ok(value) => value,
                Err(_) => continue,
            };
            total += value["body"]["exceptions"].as_array().map_or(0, Vec::len);
        }
    }
    if total > 0 {
        eprintln!(
            "blanket: {total} exception(s) recorded in .blanket/closures/*.json — \
             `blanket sync --strict` to refuse them"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::testutil::TempDir;

    /// Sync ends by registering the project as a GC root, so a path no
    /// record can hold is refused before an environment is realized or
    /// projected. Refusing at the end instead would leave the project synced,
    /// unprotected and with no way to register it.
    #[test]
    fn sync_refuses_a_project_path_no_root_record_can_hold() {
        let temp = TempDir::new();
        let project = temp.0.join("project ");
        std::fs::create_dir_all(&project).unwrap();
        let error = preflight_sync(Platform::host().unwrap(), &project).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("cannot protect"), "{error}");
    }
}

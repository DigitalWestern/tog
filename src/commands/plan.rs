//! `blanket plan`: print each detected ecosystem's plan as JSON without
//! realizing anything. Needs every tailor's plan step.

use crate::commands::shared::{no_inputs, project_dir};
use crate::kernel::context::Context;
use crate::kernel::policy;
use crate::tailors::cargo::inputs::is_cargo_here;
use crate::tailors::cargo::inputs::load_cargo_inputs;
use crate::tailors::dotnet;
use crate::tailors::elixir;
use crate::tailors::go::inputs::load_go_inputs;
use crate::tailors::node::inputs::ensure_npm_lock;
use crate::tailors::node::inputs::load_npm_plan;
use crate::tailors::python::inputs::has_python_input;
use crate::tailors::python::inputs::read_plan;
use crate::tailors::ruby;
use std::io;

pub fn run(ctx: &Context) -> io::Result<()> {
    let platform = ctx.platform;
    let store = &ctx.store;
    let dir = project_dir();
    policy::init(&dir, false)?;
    ensure_npm_lock(platform, &dir, store)?;
    let mut any = false;
    if has_python_input(&dir)? {
        let (plan, _selection, _inputs) = read_plan(platform, &dir, store)?;
        println!("{}", serde_json::to_string_pretty(&plan)?);
        any = true;
    }
    if let Some(plan) = load_npm_plan(platform, &dir)? {
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
                "ecosystem": "node", "node_version": plan.node_version,
                "lock_source": plan.lock_source, "packages": v
            }))?
        );
        any = true;
    }
    if is_cargo_here(&dir) {
        let inputs = load_cargo_inputs(platform, &dir, store)?;
        println!("{}", serde_json::to_string_pretty(&inputs.plan)?);
        any = true;
    }
    if dir.join("go.mod").is_file() {
        let inputs = load_go_inputs(platform, &dir, store)?;
        println!("{}", serde_json::to_string_pretty(&inputs.plan)?);
        any = true;
    }
    if dir.join("Gemfile").is_file() {
        let ruby_obj = ruby::ensure_ruby_for(store, platform)?;
        let (plan, _) = ruby::plan_ruby(store, &dir, &ruby_obj)?;
        println!("{}", serde_json::to_string_pretty(&plan)?);
        any = true;
    }
    if dir.join("mix.exs").is_file() {
        let beam = elixir::ensure_beam_for(store, platform)?;
        let (plan, _) = elixir::plan_elixir(store, &dir, &beam)?;
        println!("{}", serde_json::to_string_pretty(&plan)?);
        any = true;
    }
    if dotnet::has_marker(&dir)? {
        // Preflight before SDK realization: a broken layout should fail
        // loudly here, not after a toolchain download.
        dotnet::preflight(&dir)?;
        let sdk = dotnet::ensure_sdk_for(store, platform)?;
        let (plan, _) = dotnet::plan_dotnet(store, &dir, &sdk)?;
        println!("{}", serde_json::to_string_pretty(&plan)?);
        any = true;
    }
    if !any {
        return Err(no_inputs());
    }
    Ok(())
}

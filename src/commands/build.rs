//! `blanket build [ecosystem] [args...]`: a sandboxed build for the one
//! build-capable ecosystem present. Needs the cargo, go, elixir, and dotnet
//! tailors' plan/realize/project/build_sandboxed.

use crate::commands::context::Context;
use crate::commands::shared::{is_cargo_here, load_cargo_inputs, load_go_inputs, project_dir};
use crate::kernel::policy;
use crate::tailors::cargo;
use crate::tailors::dotnet;
use crate::tailors::elixir;
use crate::tailors::go;
use std::io;

/// `blanket build [ecosystem] [args...]`: explicit ecosystem, or inferred
/// when exactly one build-capable ecosystem is present (Sol review 4).
pub fn run(ctx: &Context, args: &[String]) -> io::Result<()> {
    let platform = ctx.platform;
    let store = &ctx.store;
    let cwd = project_dir();
    let (eco, rest): (&str, &[String]) = match args.first().map(String::as_str) {
        Some("cargo") => ("cargo", &args[1..]),
        Some("go") => ("go", &args[1..]),
        Some("elixir") => ("elixir", &args[1..]),
        Some("dotnet") => ("dotnet", &args[1..]),
        _ => {
            let mut present = Vec::new();
            if cwd.ancestors().any(is_cargo_here) {
                present.push("cargo");
            }
            if cwd.ancestors().any(|d| d.join("go.mod").is_file()) {
                present.push("go");
            }
            if cwd.ancestors().any(|d| d.join("mix.exs").is_file()) {
                present.push("elixir");
            }
            if dotnet::has_marker(&cwd)? {
                present.push("dotnet");
            }
            match present.as_slice() {
                [one] => (*one, args),
                [] => {
                    return Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        "blanket build requires a Cargo.toml, go.mod, or mix.exs project",
                    ))
                }
                many => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!(
                            "multiple build-capable ecosystems found ({}); specify one: \
                             `blanket build <ecosystem> ...`",
                            many.join(", ")
                        ),
                    ))
                }
            }
        }
    };
    let root = match eco {
        "cargo" => cwd
            .ancestors()
            .find(|dir| dir.join("Cargo.toml").is_file())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "no Cargo.toml found from here upward",
                )
            })?
            .to_path_buf(),
        "go" => cwd
            .ancestors()
            .find(|dir| dir.join("go.mod").is_file())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "no go.mod found from here upward")
            })?
            .to_path_buf(),
        "elixir" => cwd
            .ancestors()
            .find(|dir| dir.join("mix.exs").is_file())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "no mix.exs found from here upward")
            })?
            .to_path_buf(),
        _ => cwd.clone(),
    };
    policy::init(&root, false)?;
    match eco {
        "cargo" => {
            let inputs = load_cargo_inputs(platform, &cwd, &store)?;
            let vendor_obj = cargo::realize_vendor(&store, &inputs.plan)?;
            cargo::project_cargo_env(
                &inputs.root,
                &inputs.rust_obj,
                &vendor_obj,
                &inputs.plan,
                &inputs.lock_digest,
            )?;
            cargo::build_sandboxed(platform, &inputs.root, &inputs.rust_obj, &vendor_obj, rest)
        }
        "go" => {
            let root = cwd
                .ancestors()
                .find(|d| d.join("go.mod").is_file())
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::NotFound, "no go.mod found from here upward")
                })?
                .to_path_buf();
            let inputs = load_go_inputs(platform, &root, &store)?;
            let modcache = go::realize_modcache(&store, platform, &inputs.plan, &inputs.go_obj)?;
            go::project_go_env(
                &root,
                &inputs.go_obj,
                &modcache,
                &inputs.plan,
                &inputs.gosum_sha256,
            )?;
            go::build_sandboxed(platform, &root, &inputs.go_obj, &modcache, rest)
        }
        "elixir" => {
            let root = cwd
                .ancestors()
                .find(|d| d.join("mix.exs").is_file())
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::NotFound, "no mix.exs found from here upward")
                })?
                .to_path_buf();
            let beam = elixir::ensure_beam_for(&store, platform)?;
            let (plan, lock_sha256) = elixir::plan_elixir(&store, &root, &beam)?;
            let deps = elixir::realize_deps(&store, platform, &plan, &beam)?;
            let projection = elixir::project_elixir_env(
                platform,
                &root,
                &beam,
                &deps,
                &plan,
                &lock_sha256,
                false,
            )?;
            elixir::build_sandboxed(platform, &root, &beam, &projection, rest)
        }
        _ => {
            let sdk = dotnet::ensure_sdk_for(&store, platform)?;
            let (plan, lock_sha256) = dotnet::plan_dotnet(&store, &cwd, &sdk)?;
            let packages = dotnet::realize_packages(&store, platform, &plan, &sdk, &cwd)?;
            dotnet::project_dotnet_env(&cwd, &sdk, &packages, &plan, &lock_sha256)?;
            dotnet::build_sandboxed(platform, &cwd, &sdk, &packages, rest)
        }
    }
}

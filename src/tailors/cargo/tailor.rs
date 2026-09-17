//! The Cargo tailor's `Tailor` implementation: what `sync`, `plan`, `build`,
//! `run`, `ls`, `status`, and `sbom` do for a Cargo workspace. It also owns
//! the `rustfmt` closure that `blanket fmt` writes.

use crate::comforter;
use crate::comforter::status::{lock_state, string, State};
use crate::kernel::context::Context;
use crate::kernel::cyclonedx::{
    component, list, purl_encode, push_hash, required, toolchain_component, version_of,
};
use crate::kernel::objmeta::KindAdapter;
use crate::kernel::platform::Platform;
use crate::kernel::store;
use crate::kernel::ui;
use crate::tailors::cargo::{self as cargo, inputs, rustfmt};
use crate::tailors::{ClosureListing, PackageRow, Tailor};
use serde_json::Value;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Exit code for a finished child: its code, or 128 + signal.
fn child_status_code(status: &std::process::ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    status
        .code()
        .or_else(|| status.signal().map(|signal| 128 + signal))
        .unwrap_or(1)
}

pub struct Cargo;

impl Tailor for Cargo {
    fn id(&self) -> &'static str {
        "cargo"
    }

    fn owns_closure(&self, name: &str) -> bool {
        name == "cargo" || name == "rustfmt"
    }

    fn detect(&self, dir: &Path) -> io::Result<bool> {
        Ok(inputs::is_cargo_here(dir))
    }

    fn preflight(&self, platform: Platform, _dir: &Path) -> io::Result<()> {
        cargo::preflight_platform(platform)
    }

    fn plan(&self, ctx: &Context, dir: &Path) -> io::Result<Option<String>> {
        let inputs = inputs::load_cargo_inputs(ctx.platform, dir, &ctx.store)?;
        Ok(Some(serde_json::to_string_pretty(&inputs.plan)?))
    }

    fn sync(
        &self,
        ctx: &Context,
        dir: &Path,
        fresh: bool,
        attribution: &mut crate::kernel::policy::Attribution,
    ) -> io::Result<bool> {
        let store = &ctx.store;
        let inputs = inputs::load_cargo_inputs(ctx.platform, dir, store)?;
        let rust_obj = &inputs.rust_obj;
        let vendor_obj = cargo::realize_vendor(store, &inputs.plan)?;
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
            attribution,
        )?;
        ui::synced("cargo env", &vendor_obj);
        Ok(true)
    }

    fn builds(&self) -> bool {
        true
    }

    fn build_present(&self, cwd: &Path) -> io::Result<bool> {
        Ok(cwd.ancestors().any(inputs::is_cargo_here))
    }

    fn build_root(&self, cwd: &Path) -> io::Result<PathBuf> {
        Ok(cwd
            .ancestors()
            .find(|dir| dir.join("Cargo.toml").is_file())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "no Cargo.toml found from here upward",
                )
            })?
            .to_path_buf())
    }

    fn build(
        &self,
        ctx: &Context,
        _root: &Path,
        cwd: &Path,
        args: &[String],
        attribution: &mut crate::kernel::policy::Attribution,
    ) -> io::Result<()> {
        let store = &ctx.store;
        let inputs = inputs::load_cargo_inputs(ctx.platform, cwd, store)?;
        let vendor_obj = cargo::realize_vendor(store, &inputs.plan)?;
        cargo::project_cargo_env(
            &inputs.root,
            &inputs.rust_obj,
            &vendor_obj,
            &inputs.plan,
            &inputs.lock_digest,
            attribution,
        )?;
        cargo::build_sandboxed(
            ctx.platform,
            &inputs.root,
            &inputs.rust_obj,
            &vendor_obj,
            args,
        )
    }

    fn run_env(
        &self,
        ctx: &Context,
        dir: &Path,
        _cwd: &Path,
        _cmd: &[String],
        command: &mut Command,
    ) -> io::Result<Vec<String>> {
        let mut prefix = Vec::new();
        let cargo_home = dir.join(".blanket/cargo-home");
        if cargo_home.exists() {
            let closure = comforter::read_closure(dir, "cargo")?;
            // Store-contained resolution: a project-editable closure must never
            // inject arbitrary executable paths (Sol review 5).
            let rust_obj =
                comforter::closure_object(&ctx.store, &closure, "rust_object", "bin/rustc")?;
            prefix.push(cargo_home.join("bin").to_string_lossy().into_owned());
            prefix.push(rust_obj.join("bin").to_string_lossy().into_owned());
            command.env("CARGO_HOME", cargo_home.canonicalize()?);
            command.env_remove("RUSTUP_HOME");
            command.env_remove("RUSTUP_TOOLCHAIN");
        }
        Ok(prefix)
    }

    fn listing(&self, ecosystem: &str, body: &Value) -> ClosureListing {
        let plan = &body["plan"];
        let empty = Vec::new();
        let mut out = ClosureListing::default();
        match ecosystem {
            "cargo" => {
                out.toolchain
                    .push(("rust".into(), string(&plan["rust_version"])));
                for package in plan["crates"].as_array().unwrap_or(&empty) {
                    out.packages.push(PackageRow {
                        name: string(&package["name"]),
                        version: string(&package["version"]),
                        detail: string(&package["sha256"]),
                    });
                }
            }
            "rustfmt" => {
                let version = string(&body["rust_version"]);
                out.toolchain.push(("rustfmt".into(), version));
            }
            _ => {}
        }
        out
    }

    fn closure_state(
        &self,
        platform: Platform,
        dir: &Path,
        ecosystem: &str,
        body: &Value,
    ) -> io::Result<State> {
        Ok(match ecosystem {
            // `blanket fmt` projects nothing: its record is current when it
            // names the rustfmt this binary would use for the project now.
            "rustfmt" => rustfmt::closure_state(platform, dir, body)?,
            "cargo" => {
                if !dir.join(".blanket/cargo-home").is_dir() {
                    State::ProjectionMissing(".blanket/cargo-home".into())
                } else {
                    lock_state(dir, "Cargo.lock", &string(&body["cargo_lock_sha256"]))?
                }
            }
            _ => State::Unchecked("unknown ecosystem".into()),
        })
    }

    fn sbom_components(&self, eco: &str, body: &Value, out: &mut Vec<Value>) -> io::Result<()> {
        let plan = body.get("plan").unwrap_or(body);
        match eco {
            "cargo" => {
                for p in list(eco, plan, "crates")? {
                    let (name, ver) = (required(eco, &p, "name")?, required(eco, &p, "version")?);
                    let mut c = component(
                        &name,
                        &ver,
                        format!("pkg:cargo/{}@{}", purl_encode(&name), purl_encode(&ver)),
                        eco,
                    );
                    push_hash(&mut c, "SHA-256", &required(eco, &p, "sha256")?);
                    out.push(c);
                }
                out.push(toolchain_component(
                    body,
                    "rust_object",
                    "rust",
                    &version_of(eco, plan, "rust_version")?,
                )?);
            }
            // `blanket fmt` writes a toolchain-only closure: no packages, but two
            // store objects it pins and keeps live. Like every other arm it emits
            // the toolchain it records (rustfmt, versioned by the resolved Rust
            // version, the same pairing `blanket ls` shows) plus the paired Rust
            // object. Closures are visited in sorted name order, so a `cargo`
            // closure naming the very same Rust object has already emitted it;
            // listing it twice would inflate the inventory.
            _ => {
                let rust_version = version_of(eco, plan, "rust_version")?;
                let rust = toolchain_component(body, "rust_object", "rust", &rust_version)?;
                if !out.contains(&rust) {
                    out.push(rust);
                }
                out.push(toolchain_component(
                    body,
                    "rustfmt_object",
                    "rustfmt",
                    &rust_version,
                )?);
            }
        }
        Ok(())
    }

    fn fmt_ecosystem(&self) -> Option<&'static str> {
        Some("rust")
    }

    fn fmt_preflight(&self, platform: Platform) -> io::Result<()> {
        // A platform with no pinned component is refused here, before
        // `Store::open` and before `ensure_rust_for` downloads ~105 MB of
        // toolchain.
        rustfmt::preflight_platform(platform)
    }

    fn fmt_check_project(&self, cwd: &Path) -> io::Result<()> {
        if !cwd
            .ancestors()
            .any(|dir| dir.join("Cargo.toml").is_file() || dir.join("Cargo.lock").is_file())
        {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "no Rust project here; run `blanket fmt` from a Cargo project",
            ));
        }
        Ok(())
    }

    /// Realize only the Rust toolchain and its paired rustfmt component, then
    /// format the Cargo workspace without resolving dependencies.
    fn fmt(
        &self,
        ctx: &Context,
        cwd: &Path,
        check: bool,
        args: &[String],
        attribution: &mut crate::kernel::policy::Attribution,
    ) -> io::Result<i32> {
        let platform = ctx.platform;
        let store = &ctx.store;
        let activity = &ctx.activity;
        let rust_version = cargo::resolve_toolchain(platform, cwd)?.to_string();
        let rust_object = cargo::ensure_rust_for(store, platform, &rust_version)?;
        let rustfmt_object = rustfmt::ensure_rustfmt(store, platform, &rust_version, &rust_object)?;
        let workspace_root = inputs::locate_cargo_root(&rust_object, cwd, store)?.canonicalize()?;
        let object_ref = |path: &Path| -> io::Result<serde_json::Value> {
            let id = path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "object path has no UTF-8 id")
                })?;
            Ok(serde_json::json!({
                "path": path.display().to_string(),
                "id": id,
            }))
        };
        let rustfmt_ref = object_ref(&rustfmt_object)?;
        let inputs = rustfmt::record_inputs(rustfmt_ref["id"].as_str().unwrap_or_default());
        let mut refs = comforter::ClosureRefs::new();
        refs.object_path(store, activity, &rust_object)?;
        refs.object_path(store, activity, &rustfmt_object)?;
        comforter::write_closure(
            &workspace_root,
            "rustfmt",
            serde_json::json!({
                "rust_object": object_ref(&rust_object)?,
                "rustfmt_object": rustfmt_ref,
                "rust_version": rust_version,
                "workspace_root": workspace_root.display().to_string(),
                "inputs": inputs,
            }),
            store,
            activity,
            refs,
            attribution,
        )?;
        let invocation_dir = cwd.canonicalize()?;
        let status = rustfmt::run_sandboxed(
            platform,
            &invocation_dir,
            &workspace_root,
            &rust_object,
            &rustfmt_object,
            store,
            check,
            args,
        )?;
        Ok(child_status_code(&status))
    }

    fn object_kinds(&self) -> &'static [KindAdapter] {
        super::objects::KINDS
    }
}

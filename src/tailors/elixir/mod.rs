//! The Elixir tailor: Mix/Hex ecosystem — AST-validated lockfile (never
//! eval'd), dual-checksum-verified hex tarballs, source-tree deps projected
//! copy-on-write, four-artifact BEAM toolchain.
//!
//! mix.lock is CODE (an Elixir term literal) and Mix itself evals it, so
//! tog's planning parses it with a strict AST
//! grammar under the pinned toolchain (exact 8-field :hex tuples only —
//! atoms/strings/lists/tuples of literals, nothing callable); the Elixir
//! release zip has neither Hex nor rebar3, so both are separately pinned;
//! native deps (make/rebar3 ports) write INTO their source trees, so the
//! deps projection is a writable clonefile copy, recorded unattested.

mod check_locked;
pub mod edit;
mod hextar;
pub mod objects;
pub mod tailor;
mod tool;
mod unpack;

use unpack::extract_otp;

use crate::kernel::activity::StoreActivity;
use crate::kernel::fetch::{download_toolchain_artifact_held, download_verified_held, Digest};
use crate::kernel::fsroot::ProjectRoot;
use crate::kernel::platform::Platform;
use crate::kernel::resolve::ResolutionDoor;
use crate::kernel::sandbox::BuildSpec;
use crate::kernel::store::Store;
use crate::kernel::toolchain::document::Shipped;
#[cfg(test)]
use crate::kernel::toolchain::ArtifactRow;
use crate::kernel::toolchain::{Catalog, Selected};
use crate::kernel::types::Identity;
use crate::kernel::ui;
use check_locked::{check_locked_inputs, check_locked_passed, record_check_locked};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
pub(crate) use tool::run_checked;
use tool::{run_hexmark, run_mix};

// Linux relocation recipe revision: an identity input of the Linux toolchain
// object and of the Linux BEAM fingerprint. Bump it whenever the Install
// invocation, what gets embedded, or the verification changes, so hex-deps
// objects and `_build/tog-*` roots re-derive. Darwin never sees it.
const LINUX_RELOCATION_SCHEMA: &str = "otp-install-cross-minimal/1";

/// The shipped BEAM catalog, generated and verified by
/// `tools/catalog.py elixir`: one release bundle per `(otp, elixir)` pair,
/// the pair primary and compared OTP first. OTP is a per-platform build:
/// erlef/otp_builds on Darwin (Install already run, bin/erl at the root),
/// and on Linux our own source build in DigitalWestern/tog-toolchains
/// (hex.pm bob's Ubuntu build needs OpenSSL SM4 symbols Fedora omits), a
/// `make release` tree that is uninstalled until the relocation recipe runs
/// `Install`, with a provenance manifest alongside the asset. An OTP
/// version enters only when both builds exist. Elixir is the
/// platform-neutral `elixir-otp-<major>.zip`. Hex and rebar3 are not in
/// the Elixir release (Mix fetches them ad hoc); the generator picks them
/// by Mix's own rule over builds.hex.pm's install CSVs, so each is the
/// OTP-qualified build Mix would install (the legacy unqualified Hex is
/// compiled for old OTP and hangs on 29; no otp-29 rebar3 is published, so
/// the otp-28 escript runs on the 29 VM), keeping the sha512 hex.pm prints.
/// Platform-neutral rows repeat their one digest on both platforms.
static CATALOG: Shipped = Shipped::new(include_str!("catalog.toml"));

/// The shipped BEAM catalog and its default pair.
pub fn toolchain_catalog() -> io::Result<Catalog> {
    CATALOG.catalog()
}

pub fn preflight_platform(platform: Platform) -> io::Result<()> {
    crate::kernel::platform::require_host(platform, "BEAM toolchain")?;
    CATALOG.default_row(platform, "otp").map(|_| ())
}

/// The recipe a Darwin OTP row carries, and the one every platform-neutral
/// BEAM row (Elixir, Hex, rebar3) carries.
const BEAM_RECIPE: &str = "beam-toolchain/1";

/// One BEAM realization's bytes, read from the selected toolchain rather
/// than from the compiled pin tables. The composite object is built from
/// four independently fetched artifacts, so the spec carries all four.
#[derive(Debug)]
struct BeamSpec {
    platform: Platform,
    /// The Linux OTP row's recipe, which is also the relocation recipe the
    /// object's identity records. Darwin has no relocation step.
    relocation_schema: String,
    otp_version: String,
    otp_url: String,
    otp_sha256: String,
    elixir_version: String,
    elixir_url: String,
    elixir_sha256: String,
    hex_version: String,
    hex_url: String,
    hex_sha512: String,
    rebar3_version: String,
    rebar3_url: String,
    rebar3_sha512: String,
}

/// The selected BEAM's four rows for `platform`, refused unless this tog
/// knows every recipe involved. OTP's recipe is per platform: Darwin ships
/// an already-installed tree, Linux a make-release tree this tog relocates,
/// and the relocation recipe is an identity input.
fn beam_spec(platform: Platform, selected: &Selected) -> io::Result<BeamSpec> {
    selected.require("elixir", "otp")?;
    let otp_recipe = if platform.is_macos() {
        BEAM_RECIPE
    } else {
        LINUX_RELOCATION_SCHEMA
    };
    let otp = selected.checked_artifact(platform, "otp", otp_recipe, "sha256")?;
    let relocation_schema = if platform.is_macos() {
        String::new()
    } else {
        otp.recipe.clone()
    };
    let elixir = selected.checked_artifact(platform, "elixir", BEAM_RECIPE, "sha256")?;
    let hex = selected.checked_artifact(platform, "hex", BEAM_RECIPE, "sha512")?;
    let rebar3 = selected.checked_artifact(platform, "rebar3", BEAM_RECIPE, "sha512")?;

    Ok(BeamSpec {
        platform,
        relocation_schema,
        otp_version: otp.version.clone(),
        otp_url: otp.url.clone(),
        otp_sha256: otp.digest.hex().to_string(),
        elixir_version: elixir.version.clone(),
        elixir_url: elixir.url.clone(),
        elixir_sha256: elixir.digest.hex().to_string(),
        hex_version: hex.version.clone(),
        hex_url: hex.url.clone(),
        hex_sha512: hex.digest.hex().to_string(),
        rebar3_version: rebar3.version.clone(),
        rebar3_url: rebar3.url.clone(),
        rebar3_sha512: rebar3.digest.hex().to_string(),
    })
}

#[cfg(test)]
/// The shipped catalog's BEAM, for callers with no project selection to
/// honor. Inside a project every caller realizes from the lock instead.
fn shipped_selection() -> io::Result<Selected> {
    crate::kernel::toolchain::shipped(&toolchain_catalog()?)
}

fn beam_identity(spec: &BeamSpec, store_root: &Path) -> io::Result<Identity> {
    let mut inputs = BTreeMap::from([
        ("schema".to_string(), "beam-toolchain/1".to_string()),
        ("otp_sha256".to_string(), spec.otp_sha256.clone()),
        ("elixir_sha256".to_string(), spec.elixir_sha256.clone()),
        ("hex_sha512".to_string(), spec.hex_sha512.clone()),
        ("rebar3_sha512".to_string(), spec.rebar3_sha512.clone()),
        (
            "versions".to_string(),
            format!("hex{}:rebar{}", spec.hex_version, spec.rebar3_version),
        ),
        ("platform".to_string(), spec.platform.triple().to_string()),
    ]);
    if !spec.platform.is_macos() {
        // `Install -cross -minimal <final>` embeds the FINAL object prefix
        // (<store_root>/objects/<id>/otp) into the generated launchers, so
        // the object's bytes are a function of the store root. The root is
        // the input — never the object path, which would be circular. A
        // copy of a published object under another root is a different
        // object with a stale fallback prefix, not a relocation.
        if !store_root.is_absolute() {
            return Err(err(format!(
                "BEAM store root must be absolute: {}",
                store_root.display()
            )));
        }
        let root = store_root
            .to_str()
            .ok_or_else(|| err("BEAM store root is not valid UTF-8"))?;
        inputs.insert(
            "relocation_schema".to_string(),
            spec.relocation_schema.clone(),
        );
        inputs.insert("store_root".to_string(), root.to_string());
    }
    Ok(Identity {
        kind: "beam".into(),
        name: "beam".into(),
        version: format!("{}-elixir{}", spec.otp_version, spec.elixir_version),
        inputs,
    })
}

fn hex_deps_identity(spec: &BeamSpec, plan: &ElixirPlan) -> io::Result<Identity> {
    let mut inputs = BTreeMap::from([
        ("schema".to_string(), "hex-deps/1".to_string()),
        // .hex markers are generated under the selected toolchain; their
        // bytes live in the object.
        ("beam".to_string(), beam_fingerprint_for(spec)),
    ]);
    for d in &plan.deps {
        inputs.insert(
            format!("dep:{}", d.app),
            format!(
                "{}@{}:{}:{}:{}",
                d.package,
                d.version,
                d.outer_sha256,
                d.inner_sha256,
                d.managers.join("+")
            ),
        );
    }
    Ok(Identity {
        kind: "hex-deps".into(),
        name: "deps".into(),
        version: plan.deps.len().to_string(),
        inputs,
    })
}

fn err(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

/// A short fingerprint of the whole BEAM toolchain, used to qualify build
/// paths and identities (stale _build across toolchains is a real hazard).
fn beam_fingerprint_for(spec: &BeamSpec) -> String {
    let joined = if spec.platform.is_macos() {
        // Darwin: byte-for-byte the pre-Linux formula (golden c35290f692496d51).
        format!(
            "{}:{}:{}:{}",
            spec.otp_sha256, spec.elixir_sha256, spec.hex_sha512, spec.rebar3_sha512
        )
    } else {
        format!(
            "{}:{}:{}:{}:{}",
            spec.otp_sha256,
            spec.elixir_sha256,
            spec.hex_sha512,
            spec.rebar3_sha512,
            spec.relocation_schema
        )
    };
    fingerprint_of_joined(&joined)
}

/// The truncated digest half of `beam_fingerprint_with`, exposed so the
/// legacy-metadata adapter can recompute a candidate BEAM object's own
/// fingerprint from that object's identity inputs instead of from this
/// build's pins.
pub(crate) fn fingerprint_of_joined(joined: &str) -> String {
    hex::encode(&Sha256::digest(joined.as_bytes())[..8])
}

// ---------------------------------------------------------------------------
// Linux OTP installation (make-release tree -> installed prefix).
//
// Inspected in OTP-29.0.5 fedora44 (Install, erts-17.0.5/bin/{erl,start,
// start_erl}.src, releases/RELEASES.src). `Install [-cross] -minimal <ROOT>`:
//   without -cross   ERL_ROOT = TARGET_ERL_ROOT = <ROOT>   (physical == embedded)
//   with -cross      ERL_ROOT = `pwd`, TARGET_ERL_ROOT = <ROOT>
// i.e. -cross is the artifact's own separation between the physical tree
// being written and the prefix baked into text. Tog stages under
// <store>/tmp/stage-*/otp and publishes by rename, so it runs Install with
// cwd = staging otp and <ROOT> = the final object path computed from the
// identity (<store>/objects/<id>/otp). Nothing is rewritten afterwards; the
// staging path never enters a generated file, and verify_otp_install proves
// it. What Install generates:
//   erts-<v>/bin/erl, erts-<v>/bin/start   sed %FINAL_ROOTDIR% -> TARGET_ERL_ROOT
//                                          (erl.src also self-locates from $0 at
//                                          runtime; the embedded root is its fallback)
//   bin/erl, bin/start                     cp -p of the two above
//   bin/start_erl                          sed %EMU% -> beam; no prefix
//   releases/RELEASES                      %ERL_ROOT%/ stripped -> relative paths
//   releases/start_erl.data                "<erts_vsn> 29"
//   bin/epmd -> ../erts-<v>/bin/epmd       the only symlink in the object
//   bin/{erlc,erl_call,dialyzer,typer,ct_run,escript,run_erl,to_erl}  cp -p ELF
//   bin/{start_*.boot,no_dot_erlang.boot,start.boot,start.script}     cp -p
// The sed replacement is unescaped ("s;%FINAL_ROOTDIR%;$TARGET_ERL_ROOT;"),
// so the final prefix must not contain ';' '&' '\' or a newline.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct OtpLayout {
    erts_dir: PathBuf,
    erts_vsn: String,
}

/// Files Install writes with the embedded prefix (text, executable).
fn prefix_bearing_launchers(otp_root: &Path, layout: &OtpLayout) -> Vec<PathBuf> {
    vec![
        layout.erts_dir.join("bin/erl"),
        layout.erts_dir.join("bin/start"),
        otp_root.join("bin/erl"),
        otp_root.join("bin/start"),
    ]
}

/// Regular ELF/boot files Install copies into bin/.
const INSTALL_COPIED_BIN: &[&str] = &[
    "erlc",
    "erl_call",
    "dialyzer",
    "typer",
    "ct_run",
    "escript",
    "run_erl",
    "to_erl",
    "start.boot",
    "start.script",
    "start_clean.boot",
    "no_dot_erlang.boot",
];

fn require_regular(path: &Path, what: &str) -> io::Result<()> {
    let md = fs::symlink_metadata(path).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("OTP {what} missing at {}: {e}", path.display()),
        )
    })?;
    if !md.file_type().is_file() {
        return Err(err(format!(
            "OTP {what} at {} is not a regular file",
            path.display()
        )));
    }
    Ok(())
}

fn require_directory(path: &Path, what: &str) -> io::Result<()> {
    let md = fs::symlink_metadata(path).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("OTP {what} missing at {}: {e}", path.display()),
        )
    })?;
    if !md.file_type().is_dir() {
        return Err(err(format!(
            "OTP {what} at {} is not a directory",
            path.display()
        )));
    }
    Ok(())
}

fn read_text(path: &Path, what: &str) -> io::Result<String> {
    require_regular(path, what)?;
    let data = fs::read(path)?;
    if data.contains(&0) {
        return Err(err(format!(
            "OTP {what} at {} is binary, expected text",
            path.display()
        )));
    }
    String::from_utf8(data)
        .map_err(|_| err(format!("OTP {what} at {} is not UTF-8", path.display())))
}

fn mode_of(path: &Path) -> io::Result<u32> {
    use std::os::unix::fs::PermissionsExt;
    Ok(fs::symlink_metadata(path)?.permissions().mode() & 0o7777)
}

fn path_bytes(path: &Path) -> &[u8] {
    use std::os::unix::ffi::OsStrExt;
    path.as_os_str().as_bytes()
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

/// Validate the uninstalled make-release tree BEFORE Install runs. bin/erl
/// is deliberately not required here: Install creates it.
fn validate_otp_pre_install(otp_root: &Path, otp_version: &str) -> io::Result<OtpLayout> {
    if !otp_root.is_absolute() {
        return Err(err(format!(
            "OTP staging prefix must be absolute: {}",
            otp_root.display()
        )));
    }
    let install = otp_root.join("Install");
    let installer = read_text(&install, "Install script")?;
    // The recipe depends on these exact mechanisms; a script without them
    // is not the artifact this recipe was written against.
    for needle in [
        "#!",
        "-cross)",
        "-minimal)",
        "TARGET_ERL_ROOT",
        "%FINAL_ROOTDIR%",
    ] {
        if !installer.contains(needle) {
            return Err(err(format!(
                "OTP Install script at {} lacks {needle:?}; layout not understood by recipe {LINUX_RELOCATION_SCHEMA}",
                install.display()
            )));
        }
    }

    let mut erts_dirs = Vec::new();
    for entry in fs::read_dir(otp_root)? {
        let path = entry?.path();
        let is_erts = fs::symlink_metadata(&path)?.file_type().is_dir()
            && path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("erts-") && name.len() > "erts-".len());
        if is_erts {
            erts_dirs.push(path);
        }
    }
    if erts_dirs.len() != 1 {
        return Err(err(format!(
            "OTP tree at {} must contain exactly one erts-* directory, found {}",
            otp_root.display(),
            erts_dirs.len()
        )));
    }
    let erts_dir = erts_dirs.remove(0);
    let erts_vsn = erts_dir
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| name.strip_prefix("erts-"))
        .ok_or_else(|| {
            err(format!(
                "unexpected OTP erts directory {}",
                erts_dir.display()
            ))
        })?
        .to_string();
    let erts_bin = erts_dir.join("bin");
    require_directory(&erts_bin, "ERTS bin directory")?;
    for file in [
        "beam.smp",
        "erlexec",
        "epmd",
        "erl.src",
        "start.src",
        "start_erl.src",
    ] {
        require_regular(&erts_bin.join(file), &format!("ERTS {file}"))?;
    }
    for file in INSTALL_COPIED_BIN
        .iter()
        .filter(|f| !f.ends_with(".boot") && !f.ends_with(".script"))
    {
        require_regular(&erts_bin.join(file), &format!("ERTS {file}"))?;
    }
    for (template, token) in [
        ("erl.src", "%FINAL_ROOTDIR%"),
        ("start.src", "%FINAL_ROOTDIR%"),
    ] {
        if !read_text(&erts_bin.join(template), template)?.contains(token) {
            return Err(err(format!(
                "OTP {template} lacks the {token} template token; relocation recipe does not apply"
            )));
        }
    }

    require_directory(&otp_root.join("lib"), "library root")?;
    let major = otp_version.split('.').next().unwrap_or_default();
    if major.is_empty() || !major.bytes().all(|b| b.is_ascii_digit()) {
        return Err(err(format!("unusable OTP version {otp_version:?}")));
    }
    let release_dir = otp_root.join(format!("releases/{major}"));
    require_directory(&release_dir, &format!("OTP {major} release directory"))?;
    let version = read_text(&release_dir.join("OTP_VERSION"), "OTP version file")?;
    if version.trim() != otp_version {
        return Err(err(format!(
            "OTP version file says {:?}, expected {otp_version}",
            version.trim()
        )));
    }
    for file in [
        "start_clean.boot",
        "start_clean.script",
        "no_dot_erlang.boot",
        "start.boot",
    ] {
        require_regular(&release_dir.join(file), &format!("release {file}"))?;
    }
    let releases_src = read_text(&otp_root.join("releases/RELEASES.src"), "RELEASES.src")?;
    if !releases_src.contains("%ERL_ROOT%") {
        return Err(err("OTP RELEASES.src lacks the %ERL_ROOT% template token"));
    }
    for installed in ["bin/erl", "bin/start", "releases/RELEASES"] {
        if fs::symlink_metadata(otp_root.join(installed)).is_ok() {
            return Err(err(format!(
                "OTP tree already contains {installed}; expected an uninstalled make-release tree"
            )));
        }
    }
    Ok(OtpLayout { erts_dir, erts_vsn })
}

/// The prefix Install embeds goes through an unescaped sed replacement and
/// into sh-quoted assignments: refuse anything that would corrupt them.
fn check_embeddable_prefix(prefix: &Path) -> io::Result<&str> {
    if !prefix.is_absolute() {
        return Err(err(format!(
            "OTP final prefix must be absolute: {}",
            prefix.display()
        )));
    }
    let text = prefix
        .to_str()
        .ok_or_else(|| err("OTP final prefix is not valid UTF-8"))?;
    if let Some(bad) = text
        .chars()
        .find(|c| matches!(c, ';' | '&' | '\\' | '\n' | '\r' | '"' | '$' | '`'))
    {
        return Err(err(format!(
            "OTP final prefix contains {bad:?}, which Install's sed/sh templating cannot embed safely: {text}"
        )));
    }
    Ok(text)
}

/// Install invocation: `/bin/sh <stage>/otp/Install -cross -minimal <final>`
/// with cwd = the staged otp tree (Install -cross takes the physical root
/// from `pwd`). Writes are confined to the staged tree plus scratch.
fn otp_install_spec(otp_root: &Path, final_root: &Path, scratch: &Path) -> io::Result<BuildSpec> {
    let final_prefix = check_embeddable_prefix(final_root)?;
    let install = otp_root.join("Install");
    let install = install
        .to_str()
        .ok_or_else(|| err("OTP staging path is not valid UTF-8"))?;
    Ok(BuildSpec {
        argv: vec![
            "/bin/sh".to_string(),
            install.to_string(),
            "-cross".to_string(),
            "-minimal".to_string(),
            final_prefix.to_string(),
        ],
        cwd: otp_root.to_path_buf(),
        env: Vec::new(),
        read: Vec::new(),
        write: vec![otp_root.to_path_buf()],
        scratch: scratch.to_path_buf(),
        path: "/usr/bin:/bin".to_string(),
        host_view: crate::kernel::sandbox::HostView::Full,
    })
}

/// Execute an installer spec as a direct child: cleared environment, the
/// spec's PATH/cwd/env, HOME and TMPDIR in scratch, stdin closed (a prompt
/// must fail, not hang). This is a verified-artifact unpack step — sed, cp,
/// ln, chmod over the staged tree, the same trust class as the tar/unzip
/// calls around it, not a project build — so it does not go through the
/// build sandbox.
/// Its result is checked by verify_otp_install, including a whole-tree scan
/// for the staging prefix and a runtime probe before anything is committed.
#[cfg(test)]
fn run_installer_spec(spec: &BuildSpec) -> io::Result<()> {
    let (program, args) = spec
        .argv
        .split_first()
        .ok_or_else(|| err("installer spec has empty argv"))?;
    let mut command = Command::new(program);
    command
        .args(args)
        .current_dir(&spec.cwd)
        .env_clear()
        .env("PATH", &spec.path)
        .env("HOME", &spec.scratch)
        .env("TMPDIR", &spec.scratch)
        .env("LANG", "C")
        .stdin(std::process::Stdio::null());
    for (key, value) in &spec.env {
        command.env(key, value);
    }
    let output = command
        .output()
        .map_err(|e| io::Error::new(e.kind(), format!("spawn {program}: {e}")))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stderr = stderr.trim();
        let stderr: String = stderr.chars().take(2000).collect();
        return Err(io::Error::other(format!(
            "installer failed ({}): {:?}\n{stderr}",
            output.status, spec.argv
        )));
    }
    Ok(())
}

fn run_installer_spec_for(activity: &StoreActivity, spec: &BuildSpec) -> io::Result<()> {
    let (program, args) = spec
        .argv
        .split_first()
        .ok_or_else(|| err("installer spec has empty argv"))?;
    let mut command = Command::new(program);
    command
        .args(args)
        .current_dir(&spec.cwd)
        .env_clear()
        .env("PATH", &spec.path)
        .env("HOME", &spec.scratch)
        .env("TMPDIR", &spec.scratch)
        .env("LANG", "C")
        .stdin(std::process::Stdio::null());
    for (key, value) in &spec.env {
        command.env(key, value);
    }
    let output = crate::kernel::supervise::local_output(&mut command, activity)
        .map_err(|e| io::Error::new(e.kind(), format!("spawn {program}: {e}")))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stderr = stderr.trim();
        let stderr: String = stderr.chars().take(2000).collect();
        return Err(io::Error::other(format!(
            "installer failed ({}): {:?}\n{stderr}",
            output.status, spec.argv
        )));
    }
    Ok(())
}

#[cfg(test)]
fn run_otp_install_with<F>(
    otp_root: &Path,
    final_root: &Path,
    scratch: &Path,
    runner: F,
) -> io::Result<()>
where
    F: FnOnce(&BuildSpec) -> io::Result<()>,
{
    let spec = otp_install_spec(otp_root, final_root, scratch)?;
    runner(&spec).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!(
                "OTP Install -cross -minimal failed in staging {}: {e}",
                otp_root.display()
            ),
        )
    })
}

fn run_otp_install_with_store<F>(
    otp_root: &Path,
    final_root: &Path,
    scratch: &Path,
    runner: F,
) -> io::Result<()>
where
    F: FnOnce(&BuildSpec) -> io::Result<()>,
{
    let spec = otp_install_spec(otp_root, final_root, scratch)?;
    runner(&spec).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!(
                "OTP Install -cross -minimal failed in staging {}: {e}",
                otp_root.display()
            ),
        )
    })
}

/// Walk the whole installed tree: only regular files, directories, and
/// symlinks that resolve inside the tree; no file content or link target
/// may mention `forbidden` (the staging directory).
fn scan_tree(otp_root: &Path, forbidden: &[u8]) -> io::Result<()> {
    fn walk(root: &Path, dir: &Path, forbidden: &[u8]) -> io::Result<()> {
        for entry in fs::read_dir(dir)? {
            let path = entry?.path();
            let ft = fs::symlink_metadata(&path)?.file_type();
            if ft.is_symlink() {
                let target = fs::read_link(&path)?;
                if contains_bytes(path_bytes(&target), forbidden) {
                    return Err(err(format!(
                        "OTP symlink {} targets the staging directory ({})",
                        path.display(),
                        target.display()
                    )));
                }
                let resolved = path
                    .parent()
                    .map(|p| p.join(&target))
                    .and_then(|t| t.canonicalize().ok());
                if !resolved.is_some_and(|r| r.starts_with(root)) {
                    return Err(err(format!(
                        "OTP symlink {} -> {} does not resolve inside the OTP tree",
                        path.display(),
                        target.display()
                    )));
                }
            } else if ft.is_dir() {
                walk(root, &path, forbidden)?;
            } else if ft.is_file() {
                let data = fs::read(&path)?;
                if contains_bytes(&data, forbidden) {
                    let kind = if data.contains(&0) { "binary" } else { "text" };
                    return Err(err(format!(
                        "OTP relocation left the staging directory in {kind} file {} (recipe {LINUX_RELOCATION_SCHEMA} does not expect Install to embed the physical root)",
                        path.display()
                    )));
                }
            } else {
                return Err(err(format!(
                    "OTP tree contains a special file: {}",
                    path.display()
                )));
            }
        }
        Ok(())
    }
    let root = otp_root.canonicalize()?;
    walk(&root, &root, forbidden)
}

/// After Install, while still in staging: the generated layout is complete,
/// the launchers embed exactly the final prefix and no template token, modes
/// are executable, the epmd link is the expected relative one, and nothing
/// in the tree mentions the staging directory (the parent of otp_root, i.e.
/// <store>/tmp/stage-*, which is never a prefix of the final path).
fn verify_otp_install(otp_root: &Path, final_root: &Path, layout: &OtpLayout) -> io::Result<()> {
    let final_prefix = check_embeddable_prefix(final_root)?;
    let staging_dir = otp_root
        .parent()
        .ok_or_else(|| err("OTP staging root has no parent"))?;
    if final_root.starts_with(staging_dir) {
        return Err(err(format!(
            "OTP final prefix {} lies inside the staging directory {}",
            final_root.display(),
            staging_dir.display()
        )));
    }
    require_directory(&otp_root.join("bin"), "installed bin directory")?;
    for path in prefix_bearing_launchers(otp_root, layout) {
        let text = read_text(&path, "generated launcher")?;
        if !text.contains(final_prefix) {
            return Err(err(format!(
                "OTP launcher {} does not embed the final prefix {final_prefix}",
                path.display()
            )));
        }
        for token in ["%FINAL_ROOTDIR%", "%VSN%"] {
            if text.contains(token) {
                return Err(err(format!(
                    "OTP launcher {} still contains template token {token}",
                    path.display()
                )));
            }
        }
        if mode_of(&path)? & 0o111 != 0o111 {
            return Err(err(format!(
                "OTP launcher {} is not executable (mode {:o})",
                path.display(),
                mode_of(&path)?
            )));
        }
    }
    let start_erl = otp_root.join("bin/start_erl");
    let text = read_text(&start_erl, "start_erl")?;
    if text.contains("%EMU%") || mode_of(&start_erl)? & 0o111 != 0o111 {
        return Err(err(format!(
            "OTP start_erl at {} is not a finished launcher",
            start_erl.display()
        )));
    }
    let releases = read_text(&otp_root.join("releases/RELEASES"), "release metadata")?;
    if releases.contains("%ERL_ROOT%") || !releases.contains("\"29\"") {
        return Err(err(
            "OTP releases/RELEASES is not the installed release metadata",
        ));
    }
    let data = read_text(&otp_root.join("releases/start_erl.data"), "start_erl.data")?;
    if data.trim() != format!("{} 29", layout.erts_vsn) {
        return Err(err(format!(
            "OTP start_erl.data says {:?}, expected {:?}",
            data.trim(),
            format!("{} 29", layout.erts_vsn)
        )));
    }
    for file in INSTALL_COPIED_BIN {
        require_regular(
            &otp_root.join("bin").join(file),
            &format!("installed bin/{file}"),
        )?;
    }
    let epmd = otp_root.join("bin/epmd");
    let md = fs::symlink_metadata(&epmd)
        .map_err(|e| io::Error::new(e.kind(), format!("OTP epmd link missing: {e}")))?;
    if !md.file_type().is_symlink() {
        return Err(err(format!(
            "OTP epmd at {} is not a symlink",
            epmd.display()
        )));
    }
    let expected = PathBuf::from(format!("../erts-{}/bin/epmd", layout.erts_vsn));
    let target = fs::read_link(&epmd)?;
    if target != expected {
        return Err(err(format!(
            "OTP epmd link targets {}, expected {}",
            target.display(),
            expected.display()
        )));
    }
    scan_tree(otp_root, path_bytes(staging_dir))
}

/// Run the staged runtime once before commit: proves the ELF side loads on
/// this host (glibc floor, libcrypto/libssl symbol set — the failure mode
/// that disqualified the Ubuntu build) and that the launcher resolves its
/// root. The launcher self-locates from $0, so this works from staging.
fn probe_otp_runtime(activity: &StoreActivity, otp_root: &Path, scratch: &Path) -> io::Result<()> {
    let mut command = tool::otp_probe_command(otp_root, scratch);
    let output = crate::kernel::supervise::local_output(&mut command, activity)
        .map_err(|e| io::Error::new(e.kind(), format!("spawn staged OTP erl: {e}")))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(err(format!(
            "staged OTP runtime probe failed ({}): crypto/ssl must load on this host\nstdout: {}\nstderr: {}",
            output.status,
            stdout.trim(),
            stderr.trim().chars().take(2000).collect::<String>()
        )));
    }
    let mut lines = stdout.lines();
    let release = lines.next().unwrap_or_default();
    let root = lines.next().unwrap_or_default();
    if release != "29" {
        return Err(err(format!(
            "staged OTP reports release {release:?}, expected 29"
        )));
    }
    if Path::new(root) != otp_root.canonicalize()? {
        return Err(err(format!(
            "staged OTP code:root_dir() is {root}, expected {}",
            otp_root.display()
        )));
    }
    Ok(())
}

/// Both pinned tarballs are root-level trees (Darwin: bin/erl already
/// installed; Linux: ./Install, ./erts-*, ./lib, ./releases): no strip.
/// A new row must decide explicitly.
fn otp_strip_components(platform: Platform) -> u32 {
    match platform {
        Platform::Aarch64AppleDarwin | Platform::X86_64UnknownLinuxGnu => 0,
    }
}

#[cfg(test)]
fn extract_otp_archive(archive: &Path, destination: &Path, platform: Platform) -> io::Result<()> {
    extract_otp(None, archive, destination, platform)
}

fn extract_otp_archive_for(
    activity: &StoreActivity,
    archive: &Path,
    destination: &Path,
    platform: Platform,
) -> io::Result<()> {
    extract_otp(Some(activity), archive, destination, platform)
}

/// Realize the BEAM the selection names: OTP, Elixir, Hex and rebar3, each
/// from its own row. A catalog refresh cannot move a project's runtime,
/// because nothing here reads the pin tables.
pub fn realize_runtime(
    store: &Store,
    activity: &StoreActivity,
    platform: Platform,
    selected: &Selected,
) -> io::Result<PathBuf> {
    crate::tailors::install_kinds();
    crate::kernel::platform::require_host(platform, "BEAM toolchain")?;
    let spec = beam_spec(platform, selected)?;
    let identity = beam_identity(&spec, &store.root)?;
    let id = identity.object_id();
    if store.has_with_activity(activity, &id)? {
        crate::kernel::policy::check_cached_with_activity(store, activity, &id)?;
        return Ok(store.object_path(&id));
    }
    // Each artifact is fetched for the publisher its own row names.
    let fetch = |component: &str, url: &str, digest: &Digest| {
        let publisher = selected.artifact(platform, component)?.provider;
        download_toolchain_artifact_held(store, activity, &publisher, url, digest)
    };
    let otp_digest = Digest::sha256(&spec.otp_sha256)?;
    let otp_tar = fetch("otp", &spec.otp_url, &otp_digest)?;
    let elixir_digest = Digest::sha256(&spec.elixir_sha256)?;
    let elixir_zip = fetch("elixir", &spec.elixir_url, &elixir_digest)?;
    let hex_digest = Digest::sha512(&spec.hex_sha512)?;
    let hex_ez = fetch("hex", &spec.hex_url, &hex_digest)?;
    let rebar3_digest = Digest::sha512(&spec.rebar3_sha512)?;
    let rebar3 = fetch("rebar3", &spec.rebar3_url, &rebar3_digest)?;

    let staged = store.stage_with_activity(activity)?;
    let result = (|| {
        let otp_root = staged.join("otp");
        fs::create_dir_all(&otp_root)?;
        extract_otp_archive_for(activity, &otp_tar, &otp_root, platform)?;
        if platform.is_macos() {
            if !otp_root.join("bin/erl").is_file() {
                return Err(err("OTP extraction failed or has unexpected layout"));
            }
        } else {
            // Uninstalled make-release tree: run Install against the FINAL
            // object path (known from the identity) while writing into
            // staging, then prove the result before the ordinary commit.
            let layout = validate_otp_pre_install(&otp_root, &spec.otp_version)?;
            let final_root = store.object_path(&id).join("otp");
            let scratch = store.stage_with_activity(activity)?;
            let installed = run_otp_install_with_store(&otp_root, &final_root, &scratch, |spec| {
                run_installer_spec_for(activity, spec)
            })
            .and_then(|()| verify_otp_install(&otp_root, &final_root, &layout))
            .and_then(|()| probe_otp_runtime(activity, &otp_root, &scratch));
            let _ = crate::kernel::store::remove_tree(&scratch);
            installed?;
        }

        unpack::extract_elixir_and_hex(activity, &elixir_zip, &hex_ez, &staged, &spec.hex_version)?;
        fs::copy(&rebar3, staged.join("rebar3"))?;
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(staged.join("rebar3"), fs::Permissions::from_mode(0o755))?;
        }
        let mut deps = crate::kernel::store::ObjectDeps::new();
        deps.cache_digest(otp_digest);
        deps.cache_digest(elixir_digest);
        deps.cache_digest(hex_digest);
        deps.cache_digest(rebar3_digest);
        store
            .commit_with_activity_and_deps(activity, &identity, &staged, &[], &deps)
            .map(|(path, _)| path)
    })();
    if result.is_err() {
        let _ = crate::kernel::store::remove_tree(&staged);
    }
    result
}

/// The forced environment for every tog-controlled mix/elixir run: ERL_LIBS-
/// class vars inject code paths or emulator args before Mix's own controls
/// apply. The lists live with the host-local tripwire, which checks by them.
const ENV_REMOVE_PREFIXES: &[&str] = crate::kernel::resolve::tripwire::ELIXIR_ENV_REMOVE_PREFIXES;
const ENV_REMOVE: &[&str] = crate::kernel::resolve::tripwire::ELIXIR_ENV_REMOVE;

fn forced_env(beam_obj: &Path, deps_path: &Path, scratch_home: &Path) -> Vec<(String, String)> {
    vec![
        ("MIX_DEPS_PATH".to_string(), deps_path.display().to_string()),
        (
            "MIX_ARCHIVES".to_string(),
            beam_obj.join("archives").display().to_string(),
        ),
        (
            "MIX_REBAR3".to_string(),
            beam_obj.join("rebar3").display().to_string(),
        ),
        (
            "MIX_HOME".to_string(),
            scratch_home.join("mix").display().to_string(),
        ),
        (
            "HEX_HOME".to_string(),
            scratch_home.join("hex").display().to_string(),
        ),
        ("HEX_OFFLINE".to_string(), "1".to_string()),
        ("MIX_TARGET".to_string(), "host".to_string()),
    ]
}

/// The subdirectories of a run home that [`run_env`] points the child at.
const RUN_HOME_DIRS: &[&str] = &["mix", "hex", "xdg", "xdg-cache"];

/// Create every directory [`run_env`] names under `scratch_home`, so the
/// child starts with its whole home in place and never creates any of it.
pub fn prepare_run_home(scratch_home: &Path) -> io::Result<()> {
    for sub in RUN_HOME_DIRS {
        fs::create_dir_all(scratch_home.join(sub))?;
    }
    Ok(())
}

/// Env for `tog run` (MIX_ENV passes through from the user's shell —
/// it's on the remove-prefix list, so re-set it when present).
pub fn run_env(
    beam_obj: &Path,
    deps_path: &Path,
    build_root: &Path,
    scratch_home: &Path,
) -> io::Result<(Vec<&'static str>, Vec<&'static str>, Vec<(String, String)>)> {
    let mut set = forced_env(beam_obj, deps_path, scratch_home);
    set.push((
        "MIX_BUILD_ROOT".to_string(),
        build_root.display().to_string(),
    ));
    // Host HOME/XDG config would let rebar3 global plugins back in.
    set.push(("HOME".to_string(), scratch_home.display().to_string()));
    set.push((
        "XDG_CONFIG_HOME".to_string(),
        scratch_home.join("xdg").display().to_string(),
    ));
    set.push((
        "XDG_CACHE_HOME".to_string(),
        scratch_home.join("xdg-cache").display().to_string(),
    ));
    if let Ok(env) = std::env::var("MIX_ENV") {
        // Strict: nonempty, bounded, loud on garbage — never silently dev.
        if env.is_empty()
            || env.len() > 32
            || !env.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            return Err(err(format!("invalid MIX_ENV {env:?}")));
        }
        set.push(("MIX_ENV".to_string(), env));
    }
    Ok((ENV_REMOVE_PREFIXES.to_vec(), ENV_REMOVE.to_vec(), set))
}

fn beam_path(beam_obj: &Path) -> String {
    format!(
        "{}:{}:/usr/bin:/bin",
        beam_obj.join("elixir/bin").display(),
        beam_obj.join("otp/bin").display()
    )
}

/// Helper executed BY the pinned Elixir. Mode "lock": strict-grammar AST
/// parse of mix.lock (Code.string_to_quoted with a static atom encoder —
/// never evaluated), accepting ONLY current 8-field :hex entries, emitting
/// JSON. Mode "hexmark": writes the binary .hex marker for a dep dir.
const HELPER: &str = r##"
mode = hd(System.argv())
args = tl(System.argv())
case mode do
  "lock" ->
    [lockfile] = args
    source = File.read!(lockfile)
    if byte_size(source) > 4_000_000, do: raise("mix.lock too large")
    encoder = fn string, _meta ->
      if byte_size(string) <= 128, do: {:ok, {:atom_literal, string}}, else: {:error, "atom too long"}
    end
    {:ok, ast} = Code.string_to_quoted(source, static_atoms_encoder: encoder, existing_atoms_only: false)
    lit = fn lit, node ->
      case node do
        {:atom_literal, s} -> {:atom, s}
        s when is_binary(s) -> {:string, s}
        n when is_integer(n) -> {:int, n}
        b when is_boolean(b) -> {:bool, b}
        l when is_list(l) -> {:list, Enum.map(l, fn x -> lit.(lit, x) end)}
        {a, b} -> {:tuple, [lit.(lit, a), lit.(lit, b)]}
        {:{}, _m, elems} -> {:tuple, Enum.map(elems, fn x -> lit.(lit, x) end)}
        {:%{}, _m, pairs} -> {:map, Enum.map(pairs, fn {k, v} -> {lit.(lit, k), lit.(lit, v)} end)}
        nil -> {:atom, "nil"}
        other -> raise "mix.lock contains non-literal syntax: #{inspect(other)}"
      end
    end
    {:map, pairs} = lit.(lit, ast)
    hexre = ~r/^[0-9a-f]{64}$/
    namere = ~r/^[a-z][a-z0-9_]*$/
    entries = Enum.map(pairs, fn {k, v} ->
      app = case k do
        {:atom, a} -> a
        {:string, s} -> s
        _ -> raise "bad lock key"
      end
      unless app =~ namere, do: raise("unsafe app name #{inspect(app)}")
      case v do
        {:tuple, [{:atom, "hex"}, {:atom, pkg}, {:string, ver}, {:string, inner},
                  {:list, managers}, {:list, _deps}, {:string, "hexpm"}, {:string, outer}]} ->
          unless pkg =~ namere, do: raise("unsafe package name #{inspect(pkg)}")
          unless ver =~ ~r/^[A-Za-z0-9._+-]+$/, do: raise("unsafe version #{inspect(ver)}")
          unless inner =~ hexre and outer =~ hexre, do: raise("#{app}: checksums must be 64-hex (refresh the lock with current Hex)")
          mgrs = Enum.map(managers, fn {:atom, m} -> m; _ -> raise "bad manager" end)
          %{"app" => app, "package" => pkg, "version" => ver,
            "inner_sha256" => inner, "outer_sha256" => outer, "managers" => mgrs}
        {:tuple, [{:atom, "hex"} | rest]} ->
          raise "#{app}: unsupported hex lock entry shape (#{length(rest) + 1} fields); refresh the lock with the pinned Hex"
        {:tuple, [{:atom, "git"} | _]} ->
          raise "#{app}: git dependencies are not supported yet"
        _ ->
          raise "#{app}: unsupported lock entry"
      end
    end)
    IO.puts(JSON.encode!(%{"entries" => entries}))
  "hexmark" ->
    # .hex marker: exact shape Mix's Hex.SCM writes (decoded from a real
    # fetch): {{:hex, 2, 0}, %{name, version, managers, inner_checksum,
    # outer_checksum, repo}}. Mismatch => "lock mismatch" at compile.
    [dep_dir, name, version, inner, outer, managers_csv] = args
    allowed = %{"mix" => :mix, "rebar3" => :rebar3, "rebar" => :rebar, "make" => :make}
    managers = managers_csv |> String.split(",", trim: true)
               |> Enum.map(fn m -> Map.fetch!(allowed, m) end)
    term = {{:hex, 2, 0},
            %{name: name, version: version, managers: managers,
              inner_checksum: inner, outer_checksum: outer, repo: "hexpm"}}
    File.write!(Path.join(dep_dir, ".hex"), :erlang.term_to_binary(term))
    IO.puts("marked")
  other ->
    raise "unknown mode #{other}"
end
"##;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HexDep {
    pub app: String,
    pub package: String,
    pub version: String,
    pub inner_sha256: String,
    pub outer_sha256: String,
    pub managers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElixirPlan {
    pub otp_version: String,
    pub elixir_version: String,
    pub deps: Vec<HexDep>,
}

fn validate_plan(plan: &ElixirPlan) -> io::Result<()> {
    let name_ok = |s: &str| {
        !s.is_empty()
            && s.len() <= 128
            && s.bytes()
                .next()
                .map(|b| b.is_ascii_lowercase())
                .unwrap_or(false)
            && s.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    };
    let hex_ok = |s: &str| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit());
    let mut seen = std::collections::BTreeSet::new();
    for d in &plan.deps {
        if !name_ok(&d.app) || !name_ok(&d.package) {
            return Err(err(format!("invalid dep name in plan: {d:?}")));
        }
        if d.version.is_empty()
            || !d
                .version
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b))
        {
            return Err(err(format!("{}: invalid version", d.app)));
        }
        if !hex_ok(&d.inner_sha256) || !hex_ok(&d.outer_sha256) {
            return Err(err(format!("{}: invalid checksum", d.app)));
        }
        if !seen.insert(d.app.clone()) {
            return Err(err(format!("duplicate dep {} in plan", d.app)));
        }
        // Managers reach an atom conversion in the helper AND the .hex
        // marker bytes: closed allowlist only.
        for m in &d.managers {
            if !matches!(m.as_str(), "mix" | "rebar3" | "rebar" | "make") {
                return Err(err(format!("{}: unsupported manager {m:?}", d.app)));
            }
        }
    }
    Ok(())
}

/// The project's mix.lock text, read through the held descriptor so a
/// project directory swapped mid-sync cannot hand in another lock.
fn read_mix_lock(project: &ProjectRoot) -> io::Result<String> {
    project
        .read_input_string(Path::new("mix.lock"))?
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("{}: not found", project.path().join("mix.lock").display()),
            )
        })
}

/// The lock every plan reads, or the refusal that names it: `prepare`
/// generates it, and the command layer skips `prepare` under `--frozen`.
/// Checked before any toolchain is realized, so a frozen sync of an
/// unlocked project fails without a download.
pub fn require_lock(project: &ProjectRoot) -> io::Result<()> {
    if project.is_input_file(Path::new("mix.lock")) {
        Ok(())
    } else {
        Err(crate::tailors::missing_lock(project, "mix.lock"))
    }
}

/// `prepare`: mix.lock, resolved by the store mix (planner scratch,
/// network, unsandboxed) when there is none. The one place the Elixir
/// tailor writes project inputs.
pub fn generate_lock(
    door: &mut ResolutionDoor<'_>,
    project: &ProjectRoot,
    beam_obj: &Path,
) -> io::Result<()> {
    if !project.is_input_file(Path::new("mix.exs")) {
        return Err(err("mix.exs not found"));
    }
    ui::note("no mix.lock; resolving with the store mix (network, unsandboxed)...");
    let scratch = door.store().stage_with_activity(door.lease())?;
    let out = run_mix(
        door,
        beam_obj,
        project.path(),
        &scratch,
        false,
        &["mix", "deps.get"],
    )?;
    let _ = crate::kernel::store::remove_tree(&scratch);
    if !out.status.success() {
        return Err(err(format!(
            "store mix deps.get failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(())
}

/// Plan: AST-parse mix.lock under the pinned toolchain (lock-only, no
/// eval). The project is read through the held descriptor; mix itself
/// still runs in `project.path()`.
pub fn plan_elixir(
    door: &mut ResolutionDoor<'_>,
    project: &ProjectRoot,
    beam_obj: &Path,
    selected: &Selected,
) -> io::Result<(ElixirPlan, String)> {
    let (store, activity) = (door.store(), door.lease());
    if !project.is_input_file(Path::new("mix.exs")) {
        return Err(err("mix.exs not found"));
    }
    require_lock(project)?;
    let project_dir = project.path();
    let lock = read_mix_lock(project)?;
    let inputs = check_locked_inputs(project, beam_obj, &lock)?;
    let unchanged = match &inputs {
        Some(inputs) => check_locked_passed(store, project, inputs)?,
        None => false,
    };
    if unchanged {
        ui::trace("mix.exs and mix.lock unchanged since their last passing check");
    } else {
        // Consistency gate: exit status only (this evaluates mix.exs —
        // delegated trust, never artifact authority). Network-permitted
        // (plan-phase doctrine): --check-locked needs the hex registry; a
        // persistent planner HEX_HOME keeps it warm.
        let planner_home = store.root.join("planner-hexhome");
        fs::create_dir_all(&planner_home)?;
        let out = run_mix(
            door,
            beam_obj,
            project_dir,
            &planner_home,
            false,
            &["mix", "deps.get", "--check-locked"],
        )?;
        if !out.status.success() {
            return Err(err(format!(
                "mix.exs and mix.lock are out of sync; run `tog run mix \
                 deps.get` and retry\n{}",
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        // Recorded only when the inputs still hash the same after the
        // check, so the record names the bytes the check actually read.
        let after = check_locked_inputs(project, beam_obj, &read_mix_lock(project)?)?;
        if let (Some(before), Some(after)) = (&inputs, &after) {
            if before == after {
                record_check_locked(store, activity, project, before);
            }
        }
    }
    let scratch = store.stage_with_activity(activity)?;
    let helper = scratch.join("helper.exs");
    fs::write(&helper, HELPER)?;
    // The helper parses a copy of the bytes read through the held
    // descriptor, so what it parses is exactly what is hashed below.
    let lock_copy = scratch.join("mix.lock");
    fs::write(&lock_copy, &lock)?;
    let out = run_mix(
        door,
        beam_obj,
        project_dir,
        &scratch,
        true,
        &[
            "elixir",
            helper
                .to_str()
                .ok_or_else(|| err("helper path not UTF-8"))?,
            "lock",
            lock_copy.to_str().ok_or_else(|| err("path not UTF-8"))?,
        ],
    )?;
    let _ = crate::kernel::store::remove_tree(&scratch);
    if !out.status.success() {
        return Err(err(format!(
            "mix.lock analysis failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    #[derive(Deserialize)]
    struct HelperOut {
        entries: Vec<HexDep>,
    }
    let parsed: HelperOut =
        serde_json::from_slice(&out.stdout).map_err(|e| err(format!("helper output: {e}")))?;
    let mut deps = parsed.entries;
    deps.sort_by(|a, b| a.app.cmp(&b.app));
    let plan = ElixirPlan {
        // The toolchain this plan was made under is the selected one, so
        // the plan records the selection's versions, never the shipped pins.
        otp_version: selected.version("otp")?.to_string(),
        elixir_version: selected.version("elixir")?.to_string(),
        deps,
    };
    validate_plan(&plan)?;
    let now = read_mix_lock(project)?;
    if now != lock {
        return Err(err("mix.lock changed while planning; re-run 'tog'"));
    }
    Ok((plan, hex::encode(Sha256::digest(lock.as_bytes()))))
}

/// Realize the immutable deps-source object (kind "hex-deps"): every
/// tarball dual-checksum-verified by tog (outer = sha256 of the .tar,
/// inner = sha256(VERSION ++ metadata.config ++ contents.tar.gz)).
pub fn realize_deps(
    store: &Store,
    activity: &StoreActivity,
    platform: Platform,
    plan: &ElixirPlan,
    beam_obj: &Path,
    selected: &Selected,
) -> io::Result<PathBuf> {
    crate::tailors::install_kinds();
    crate::kernel::platform::require_host(platform, "Hex dependencies")?;
    let spec = beam_spec(platform, selected)?;
    validate_plan(plan)?;
    let identity = hex_deps_identity(&spec, plan)?;
    let id = identity.object_id();
    if store.has_with_activity(activity, &id)? {
        crate::kernel::policy::check_cached_with_activity(store, activity, &id)?;
        return Ok(store.object_path(&id));
    }

    let scratch = store.stage_with_activity(activity)?;
    let helper = scratch.join("helper.exs");
    fs::write(&helper, HELPER)?;
    let staged = store.stage_with_activity(activity)?;
    for d in &plan.deps {
        let url = format!(
            "https://repo.hex.pm/tarballs/{}-{}.tar",
            d.package, d.version
        );
        let tar = download_verified_held(store, activity, &url, &d.outer_sha256)
            .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", d.app)))?;
        let dep_dir = hextar::unpack_verified(activity, &tar, &scratch, &staged, d)?;
        // .hex marker via the pinned toolchain (ETF binary).
        let out = run_hexmark(
            activity,
            beam_obj,
            &scratch,
            &[
                "elixir",
                helper.to_str().unwrap(),
                "hexmark",
                dep_dir.to_str().ok_or_else(|| err("dep path not UTF-8"))?,
                &d.package,
                &d.version,
                &d.inner_sha256,
                &d.outer_sha256,
                &d.managers.join(","),
            ],
        )?;
        if !out.status.success() {
            return Err(err(format!(
                "{}: .hex marker generation failed: {}",
                d.app,
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
    }
    let _ = crate::kernel::store::remove_tree(&scratch);
    let mut deps = crate::kernel::store::ObjectDeps::new();
    deps.object_id(&crate::kernel::store::object_id_from_path(beam_obj)?)?;
    for dep in &plan.deps {
        deps.cache_digest(Digest::sha256(&dep.outer_sha256)?);
    }
    store
        .commit_with_activity_and_deps(activity, &identity, &staged, &[], &deps)
        .map(|(path, _)| path)
}

/// The ONE forest path a project's deps projection may live at: derived
/// from the canonical project dir and the deps object id, never from
/// closure-recorded strings.
pub fn expected_projection(
    store: &Store,
    project_dir: &Path,
    deps_obj: &Path,
) -> io::Result<PathBuf> {
    let key = Store::project_key(project_dir)?;
    let obj_id = deps_obj
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| err("deps object id not UTF-8"))?;
    Ok(store
        .root
        .join("forests")
        .join(key)
        .join(obj_id)
        .join("hex-deps"))
}

/// Project: clonefile the deps object into a writable per-project tree
/// (native builds write into their source dirs — npm mutablePackages
/// precedent; recorded unattested) + closure envelope.
pub fn project_elixir_env(
    activity: &StoreActivity,
    platform: Platform,
    project: &ProjectRoot,
    beam_obj: &Path,
    deps_obj: &Path,
    plan: &ElixirPlan,
    lock_sha256: &str,
    fresh: bool,
    selected: &Selected,
    attribution: &mut crate::kernel::policy::Attribution,
) -> io::Result<PathBuf> {
    let spec = beam_spec(platform, selected)?;
    let beam_obj = beam_obj.canonicalize()?;
    let deps_obj = deps_obj.canonicalize()?;
    let store = crate::comforter::store_from_object_path(&beam_obj)
        .ok_or_else(|| err("BEAM object is not in a Tog store"))?;
    let project_dir = project.path();
    let proj_dir = expected_projection(&store, project_dir, &deps_obj)?;
    let project_lock = store.project_lock_in(project)?;
    store.ensure_namespace(Path::new("forests"))?;
    let mut refs = crate::comforter::ClosureRefs::new();
    refs.object_path(&store, activity, &beam_obj)?;
    refs.object_path(&store, activity, &deps_obj)?;
    refs.forest(&store, activity, &proj_dir)?;
    // Protect the dependency projection before cloning or publishing it.
    crate::comforter::persist_root_for_refs_with_project_lock(
        project,
        &store,
        activity,
        &refs,
        &project_lock,
    )?;
    if fresh && proj_dir.exists() {
        crate::kernel::store::remove_tree(&proj_dir)?;
    }
    if !proj_dir.exists() {
        // Atomic publication: clone into a tmp sibling, then rename — a
        // crashed clone must never be trusted as a complete forest.
        let parent = proj_dir.parent().unwrap();
        fs::create_dir_all(parent)?;
        let tmp = parent.join(format!(
            ".hex-deps.tmp.{}",
            crate::kernel::fsroot::random_suffix()?
        ));
        crate::comforter::clone_tree_with_activity(activity, &deps_obj, &tmp, platform)?;
        fs::rename(&tmp, &proj_dir)?;
    }
    crate::comforter::write_closure_with_project_lock(
        project,
        "elixir",
        closure_body(
            &beam_obj,
            &deps_obj,
            &proj_dir,
            plan,
            lock_sha256,
            &spec,
            selected,
        )?,
        &store,
        activity,
        refs,
        &project_lock,
        attribution,
    )?;
    Ok(proj_dir)
}

/// The Elixir closure body: the projection's objects and plan, the
/// toolchain fingerprint `tog run` reconstructs the build root from, and
/// the toolchain record that says which selection realized them. The BEAM
/// object is this ecosystem's runtime, and `project_elixir_env` already
/// holds it as a direct ref, so GC keeps it alive by the recorded id.
#[allow(clippy::too_many_arguments)]
fn closure_body(
    beam_obj: &Path,
    deps_obj: &Path,
    proj_dir: &Path,
    plan: &ElixirPlan,
    lock_sha256: &str,
    spec: &BeamSpec,
    selected: &Selected,
) -> io::Result<serde_json::Value> {
    let mut body = serde_json::json!({
        "beam_object": crate::comforter::object_ref(beam_obj)?,
        "deps_object": crate::comforter::object_ref(deps_obj)?,
        "deps_projection": proj_dir.display().to_string(),
        "mutable_state": "unattested",
        "mix_lock_sha256": lock_sha256,
        "beam_fingerprint": beam_fingerprint_for(spec),
        "plan": plan,
    });
    let record = crate::comforter::toolchain::closure_record(selected, beam_obj);
    crate::comforter::merge_record(&mut body, record);
    Ok(body)
}

/// Build root, qualified by the toolchain fingerprint: stale BEAM/native
/// artifacts across OTP/Elixir upgrades are a real hazard.
pub fn build_root_at(project_dir: &Path, fingerprint: &str) -> PathBuf {
    project_dir.join(format!("_build/tog-{fingerprint}"))
}

/// The build root of the selected toolchain.
pub fn build_root(
    platform: Platform,
    project_dir: &Path,
    selected: &Selected,
) -> io::Result<PathBuf> {
    Ok(build_root_at(
        project_dir,
        &beam_fingerprint_for(&beam_spec(platform, selected)?),
    ))
}

/// Sandboxed `mix compile`: network denied, writes only the qualified
/// build root, the deps projection (native builds write in-tree), scratch.
pub fn build_sandboxed(
    platform: Platform,
    activity: &StoreActivity,
    project_dir: &Path,
    beam_obj: &Path,
    deps_projection: &Path,
    args: &[String],
    selected: &Selected,
) -> io::Result<()> {
    for arg in args {
        let norm = arg.trim_start_matches('-');
        if norm.starts_with("deps-path") || norm.starts_with("build-path") {
            return Err(err(format!("{arg}: this flag is managed by tog")));
        }
    }
    let project_dir = project_dir.canonicalize()?;
    let beam_obj = beam_obj.canonicalize()?;
    let deps_projection = deps_projection.canonicalize()?;
    let store = Store::open()?;
    store.require_activity(activity, "mix build")?;
    let scratch = store.stage_with_activity(activity)?;
    let build = build_root(platform, &project_dir, selected)?;
    fs::create_dir_all(&build)?;
    let build = build.canonicalize()?;
    let mut argv = vec![
        beam_obj.join("elixir/bin/mix").display().to_string(),
        "compile".to_string(),
    ];
    argv.extend(args.iter().cloned());
    let mut env = forced_env(&beam_obj, &deps_projection, &scratch);
    env.push(("MIX_BUILD_ROOT".to_string(), build.display().to_string()));
    env.push(("MIX_ENV".to_string(), "dev".to_string()));
    // Mix's compilation lock runs over loopback TCP — denied in-sandbox.
    // The sandboxed build is single-flight anyway (store-serialized).
    env.push(("MIX_OS_CONCURRENCY_LOCK".to_string(), "false".to_string()));
    let spec = BuildSpec {
        argv,
        cwd: project_dir.clone(),
        env,
        read: vec![project_dir.clone(), beam_obj.clone()],
        write: vec![build, deps_projection.clone()],
        scratch: scratch.clone(),
        path: beam_path(&beam_obj),
        host_view: crate::kernel::sandbox::HostView::Full,
    };
    let result = crate::kernel::sandbox::run_build_spec_on(platform, &spec, Some(activity))
        .map_err(|e| {
            io::Error::new(
                e.kind(),
                format!(
                    "mix compile failed: {e}\n(network is denied during builds; deps \
             needing network at compile time or absent host libraries are \
             unsupported in v0)"
                ),
            )
        });
    let _ = crate::kernel::store::remove_tree(&scratch);
    result
}

/// The shipped default pair's artifacts, the goldens every BEAM object id
/// test is written against: adding a newer pair to the catalog must not
/// move them, and `the_default_pair_is_unchanged` holds the catalog to them.
#[cfg(test)]
const OTP_VERSION: &str = "29.0.5";
#[cfg(test)]
const ELIXIR_VERSION: &str = "1.20.4";
#[cfg(test)]
const ELIXIR_URL: &str =
    "https://github.com/elixir-lang/elixir/releases/download/v1.20.4/elixir-otp-29.zip";
#[cfg(test)]
const ELIXIR_SHA256: &str = "7863c546cda13fecc949e562e326042451dacf8fd8698a36783cb71eeb223b46";
#[cfg(test)]
const HEX_VERSION: &str = "2.5.1";
#[cfg(test)]
const HEX_URL: &str = "https://builds.hex.pm/installs/1.20.0/hex-2.5.1-otp-29.ez";
#[cfg(test)]
const HEX_SHA512: &str = "6629f4b4bb2e040326151ebb853aad065e342c65ad3a0f2a2674dcf7164eb4328d6c929513d7230309ad75042024e72bef0e0a51ebff373b4173d2746b1772b7";
#[cfg(test)]
const REBAR3_VERSION: &str = "3.25.1";
#[cfg(test)]
const REBAR3_URL: &str = "https://builds.hex.pm/installs/1.18.4/rebar3-3.25.1-otp-28";
#[cfg(test)]
const REBAR3_SHA512: &str = "992fd755b7926fae455e5e07d9d195f4d3e7f181609eed1b9cabfe548624df10d148cd4b59bda40bebb185d3d68f9a9fd68a70b294101c8ad9cf0fadcc683d24";

/// The default pair's OTP row for a platform.
#[cfg(test)]
fn otp_pin(platform: Platform) -> io::Result<&'static ArtifactRow> {
    CATALOG.default_row(platform, "otp")
}

/// A spec from the golden default pair: the fixture the identity goldens
/// are written against.
#[cfg(test)]
fn pin_spec_with(platform: Platform, relocation_schema: &str) -> BeamSpec {
    let pin = otp_pin(platform).expect("pinned BEAM toolchain for test platform");
    BeamSpec {
        platform: pin.platform,
        relocation_schema: relocation_schema.to_string(),
        otp_version: OTP_VERSION.to_string(),
        otp_url: pin.url.to_string(),
        otp_sha256: pin.digest.hex().to_string(),
        elixir_version: ELIXIR_VERSION.to_string(),
        elixir_url: ELIXIR_URL.to_string(),
        elixir_sha256: ELIXIR_SHA256.to_string(),
        hex_version: HEX_VERSION.to_string(),
        hex_url: HEX_URL.to_string(),
        hex_sha512: HEX_SHA512.to_string(),
        rebar3_version: REBAR3_VERSION.to_string(),
        rebar3_url: REBAR3_URL.to_string(),
        rebar3_sha512: REBAR3_SHA512.to_string(),
    }
}

#[cfg(test)]
fn pin_spec(platform: Platform) -> BeamSpec {
    pin_spec_with(platform, LINUX_RELOCATION_SCHEMA)
}

#[cfg(test)]
pub(crate) fn live_identity_cases(platform: Platform) -> Vec<Identity> {
    let spec = pin_spec(platform);
    let beam =
        beam_identity(&spec, Path::new("/fixture/tog-store")).expect("offline BEAM identity");
    let empty_plan = ElixirPlan {
        otp_version: OTP_VERSION.into(),
        elixir_version: ELIXIR_VERSION.into(),
        deps: Vec::new(),
    };
    let dependency_plan = ElixirPlan {
        deps: vec![HexDep {
            app: "jason".into(),
            package: "jason".into(),
            version: "1.4.4".into(),
            inner_sha256: "a".repeat(64),
            outer_sha256: "b".repeat(64),
            managers: vec!["mix".into()],
        }],
        ..empty_plan.clone()
    };
    let hex_empty = hex_deps_identity(&spec, &empty_plan).expect("empty Hex identity");
    let hex_dependency =
        hex_deps_identity(&spec, &dependency_plan).expect("Hex dependency identity");
    vec![beam, hex_empty, hex_dependency]
}

#[cfg(test)]
mod tests {

    /// The host-local tripwire admits this helper by content: the digest
    /// it holds is the digest of the text written here, so an edit to the
    /// helper is also an edit to the reviewed table.
    #[test]
    fn the_tripwire_pins_this_helper() {
        use sha2::Digest as _;
        assert_eq!(
            hex::encode(sha2::Sha256::digest(HELPER.as_bytes())),
            crate::kernel::resolve::tripwire::ELIXIR_HELPER_SHA256
        );
    }

    /// The real host-local call sites pass the tripwire, and an Erlang or
    /// Elixir option variable added to either is refused.
    #[test]
    fn hexmark_and_the_otp_probe_pass_the_tripwire_only_as_built() {
        use crate::kernel::resolve::tripwire::refusal;
        use crate::kernel::testutil::{loosened, store_program};
        let store = TempDir::named("elixir-tripwire");
        let refused = |command: &Command| refusal(command, &store.0);
        store_program(&store.0, "objects/beam/elixir/bin/elixir");
        let beam = store.0.join("objects/beam");
        let scratch = store.0.join("tmp/stage-scratch");
        fs::create_dir_all(&scratch).unwrap();
        let helper = scratch.join("helper.exs");
        fs::write(&helper, HELPER).unwrap();
        let dep = scratch.join("deps/jason");
        let args = |dep: &Path| {
            [
                "elixir",
                helper.to_str().unwrap(),
                "hexmark",
                dep.to_str().unwrap(),
                "jason",
                "1.4.4",
                "inner",
                "outer",
                "mix",
            ]
            .map(str::to_string)
        };
        let build_at = |beam: &Path, dep: &Path| {
            let args = args(dep);
            let args: Vec<&str> = args.iter().map(String::as_str).collect();
            tool::hexmark_command(beam, &scratch, &args)
        };
        let build = || build_at(&beam, &dep);
        assert!(refused(&build()).is_none(), "{:?}", refused(&build()));
        for (key, value) in [
            ("ELIXIR_ERL_OPTIONS", "-eval halt()"),
            ("ERL_AFLAGS", "-eval halt()"),
            ("ERTS_BIN", "/tmp/erts/"),
            ("MIX_EXS", "/tmp/mix.exs"),
            ("HEX_MIRROR", "https://example.com"),
        ] {
            let mut command = build();
            command.env(key, value);
            assert!(refused(&command).is_some(), "{key}");
        }
        let loosened_hexmark = loosened(build);
        let keys: Vec<&str> = loosened_hexmark
            .iter()
            .map(|(key, _)| key.as_str())
            .collect();
        for key in [
            "PATH",
            "HOME",
            "TMPDIR",
            "XDG_CONFIG_HOME",
            "HEX_OFFLINE",
            "MIX_HOME",
        ] {
            assert!(keys.contains(&key), "{key} is not forced: {keys:?}");
        }
        for (key, command) in &loosened_hexmark {
            assert!(refused(command).is_some(), "loosened {key}");
        }
        let online = {
            let args = args(&dep);
            let args: Vec<&str> = args.iter().map(String::as_str).collect();
            tool::mix_spec(&beam, &scratch, &scratch, false, &args).command()
        };
        assert!(refused(&online).is_some(), "hexmark without HEX_OFFLINE");
        // Another mode, an option word, or another script at the helper's
        // path, each in the environment as built.
        let (helper_arg, dep_arg) = (helper.to_str().unwrap(), dep.to_str().unwrap());
        for argv in [
            [
                "elixir", helper_arg, "lock", dep_arg, "jason", "1.4.4", "inner", "outer", "mix",
            ],
            [
                "elixir", helper_arg, "hexmark", dep_arg, "-e", "1.4.4", "inner", "outer", "mix",
            ],
        ] {
            let command = tool::hexmark_command(&beam, &scratch, &argv);
            assert!(refused(&command).is_some(), "{argv:?}");
        }
        fs::write(&helper, "IO.puts(:not_the_helper)\n").unwrap();
        assert!(refused(&build()).is_some(), "an impostor helper.exs");
        fs::write(&helper, HELPER).unwrap();
        assert!(refused(&build()).is_none());
        assert!(
            refused(&build_at(&beam, Path::new("/tmp/dep"))).is_some(),
            "a dependency outside the store"
        );
        let host = TempDir::named("elixir-tripwire-host");
        store_program(&host.0, "beam/elixir/bin/elixir");
        assert!(
            refused(&build_at(&host.0.join("beam"), &dep)).is_some(),
            "an elixir outside the store"
        );

        store_program(&store.0, "tmp/stage-otp/otp/bin/erl");
        let otp = store.0.join("tmp/stage-otp/otp");
        let probe = || tool::otp_probe_command(&otp, &scratch);
        assert!(refused(&probe()).is_none(), "{:?}", refused(&probe()));
        for (key, value) in [
            ("ERL_AFLAGS", "-eval 'halt(3).'"),
            ("XDG_CONFIG_HOME", "/tmp"),
        ] {
            let mut command = probe();
            command.env(key, value);
            assert!(refused(&command).is_some(), "{key}");
        }
        for (key, command) in &loosened(probe) {
            assert!(refused(command).is_some(), "loosened {key}");
        }
        store_program(&host.0, "otp/bin/erl");
        let host_probe = tool::otp_probe_command(&host.0.join("otp"), &scratch);
        assert!(refused(&host_probe).is_some(), "an erl outside the store");
    }
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    const DARWIN_OBJECT_ID: &str =
        "7859ae4c9aa35b6c24bd08c2ad7989ab13313a8b-beam-29.0.5-elixir1.20.4";
    const DARWIN_FINGERPRINT: &str = "c35290f692496d51";
    const LINUX: Platform = Platform::X86_64UnknownLinuxGnu;
    const DARWIN: Platform = Platform::Aarch64AppleDarwin;

    use crate::kernel::testutil::TempDir;

    // ---- pins / identity / fingerprint -----------------------------------

    #[test]
    fn darwin_identity_unchanged() {
        let spec = pin_spec(DARWIN);
        let identity = beam_identity(&spec, Path::new("/unused")).unwrap();
        assert_eq!(identity.object_id(), DARWIN_OBJECT_ID);
        assert_eq!(beam_fingerprint_for(&spec), DARWIN_FINGERPRINT);
        // Darwin inputs: exactly the pre-Linux set, no recipe/store-root keys.
        assert_eq!(identity.inputs.len(), 7);
        assert!(!identity.inputs.contains_key("relocation_schema"));
        assert!(!identity.inputs.contains_key("store_root"));
        // Neither the recipe revision nor the store root moves Darwin.
        let other = pin_spec_with(DARWIN, "otp-install-cross-minimal/99");
        assert_eq!(
            beam_identity(&other, Path::new("/x")).unwrap().object_id(),
            DARWIN_OBJECT_ID
        );
        assert_eq!(beam_fingerprint_for(&other), DARWIN_FINGERPRINT);
    }

    #[test]
    fn the_default_pair_is_unchanged() {
        let catalog = toolchain_catalog().unwrap();
        assert!(
            catalog.bundles().len() > 1,
            "the catalog holds more than the default"
        );
        for bundle in catalog.bundles() {
            for platform in Platform::ALL {
                for component in ["otp", "elixir", "hex", "rebar3"] {
                    assert!(bundle.artifact(*platform, component).is_some());
                }
            }
        }
        let selected = shipped_selection().unwrap();
        assert_eq!(selected.version("otp").unwrap(), OTP_VERSION);
        assert_eq!(selected.version("elixir").unwrap(), ELIXIR_VERSION);
        assert_eq!(selected.version("hex").unwrap(), HEX_VERSION);
        assert_eq!(selected.version("rebar3").unwrap(), REBAR3_VERSION);
        let darwin = otp_pin(DARWIN).unwrap();
        assert_eq!(
            darwin.url,
            "https://github.com/erlef/otp_builds/releases/download/OTP-29.0.5/otp-aarch64-apple-darwin.tar.gz"
        );
        assert_eq!(
            darwin.digest.hex(),
            "24b9e00da2b9ad25b1f182e2efd73ff316e46ec4b143c0cc3c69dbd27d5a594d"
        );
        let linux = otp_pin(LINUX).unwrap();
        assert_eq!(
            linux.url,
            "https://github.com/DigitalWestern/tog-toolchains/releases/download/otp-29.0.5-x86_64-unknown-linux-gnu-fedora44/OTP-29.0.5-x86_64-unknown-linux-gnu-fedora44.tar.gz"
        );
        assert_eq!(
            linux.digest.hex(),
            "18ae1abc8fd39306c502e9a7fd6885df3125f56d783cb577057ec29ad17d01c4"
        );
        // Platform-neutral artifacts: the same row on both platforms, and
        // the goldens above.
        for platform in Platform::ALL {
            let row = |component| selected.artifact(*platform, component).unwrap();
            assert_eq!(row("elixir").url, ELIXIR_URL);
            assert_eq!(row("elixir").digest.hex(), ELIXIR_SHA256);
            assert_eq!(row("hex").url, HEX_URL);
            assert_eq!(row("hex").digest.hex(), HEX_SHA512);
            assert_eq!(row("rebar3").url, REBAR3_URL);
            assert_eq!(row("rebar3").digest.hex(), REBAR3_SHA512);
        }
        assert!(preflight_platform(Platform::host().unwrap()).is_ok());
    }

    #[test]
    fn linux_identity_is_separate_and_tracks_recipe_and_store_root() {
        let root = Path::new("/srv/tog/store");
        let linux = beam_identity(&pin_spec(LINUX), root).unwrap();
        let darwin = beam_identity(&pin_spec(DARWIN), root).unwrap();
        assert_ne!(linux.object_id(), darwin.object_id());
        assert_eq!(linux.inputs["platform"], "x86_64-unknown-linux-gnu");
        assert_eq!(linux.inputs["relocation_schema"], LINUX_RELOCATION_SCHEMA);
        assert_eq!(linux.inputs["store_root"], "/srv/tog/store");
        for key in ["otp_sha256", "elixir_sha256", "hex_sha512", "rebar3_sha512"] {
            assert!(linux.inputs.contains_key(key), "{key}");
        }
        assert_eq!(linux.inputs["otp_sha256"], pin_spec(LINUX).otp_sha256);
        // The object path itself is never an input (would be circular).
        assert!(!linux.inputs.values().any(|v| v.contains("/objects/")));

        let other_root = beam_identity(&pin_spec(LINUX), Path::new("/other/store")).unwrap();
        assert_ne!(other_root.object_id(), linux.object_id());
        let other_schema =
            beam_identity(&pin_spec_with(LINUX, "otp-install-cross-minimal/2"), root).unwrap();
        assert_ne!(other_schema.object_id(), linux.object_id());
        assert!(beam_identity(&pin_spec(LINUX), Path::new("relative")).is_err());
    }

    #[test]
    fn linux_fingerprint_and_build_root_track_recipe() {
        let linux = beam_fingerprint_for(&pin_spec(LINUX));
        assert_eq!(linux.len(), 16);
        assert_ne!(linux, DARWIN_FINGERPRINT);
        assert_ne!(
            beam_fingerprint_for(&pin_spec_with(LINUX, "otp-install-cross-minimal/2")),
            linux
        );
        let linux_root = build_root_at(Path::new("/p"), &linux);
        let darwin_root = build_root_at(Path::new("/p"), &beam_fingerprint_for(&pin_spec(DARWIN)));
        assert_eq!(
            linux_root,
            Path::new("/p").join(format!("_build/tog-{linux}"))
        );
        assert_eq!(
            darwin_root,
            Path::new("/p").join(format!("_build/tog-{DARWIN_FINGERPRINT}"))
        );
        assert_ne!(linux_root, darwin_root);
    }

    // ---- extraction ------------------------------------------------------

    /// Synthetic tar.gz with root-level entries, packed like the pinned
    /// artifacts (`tar -C tree -czf out .`).
    fn pack(tree: &Path, out: &Path) {
        let status = Command::new("/usr/bin/tar")
            .arg("-C")
            .arg(tree)
            .arg("-czf")
            .arg(out)
            .arg(".")
            .status()
            .unwrap();
        assert!(status.success());
    }

    #[test]
    fn both_platforms_extract_root_level_trees_without_strip() {
        assert_eq!(otp_strip_components(DARWIN), 0);
        assert_eq!(otp_strip_components(LINUX), 0);
        let temp = TempDir::named("extract");
        // Linux-shaped: uninstalled tree.
        let linux_tree = temp.0.join("linux-tree");
        fs::create_dir_all(linux_tree.join("erts-17.0.5/bin")).unwrap();
        fs::write(linux_tree.join("Install"), "#!/bin/sh\n").unwrap();
        fs::write(linux_tree.join("erts-17.0.5/bin/erl.src"), "x").unwrap();
        let linux_tar = temp.0.join("linux.tar.gz");
        pack(&linux_tree, &linux_tar);
        let linux_out = temp.0.join("linux-out");
        fs::create_dir_all(&linux_out).unwrap();
        extract_otp_archive(&linux_tar, &linux_out, LINUX).unwrap();
        assert!(linux_out.join("Install").is_file());
        assert!(linux_out.join("erts-17.0.5/bin/erl.src").is_file());
        assert!(
            !linux_out.join("bin/erl").exists(),
            "pre-install: no bin/erl yet"
        );
        // Darwin-shaped: installed tree.
        let darwin_tree = temp.0.join("darwin-tree");
        fs::create_dir_all(darwin_tree.join("bin")).unwrap();
        fs::write(darwin_tree.join("bin/erl"), "#!/bin/sh\n").unwrap();
        let darwin_tar = temp.0.join("darwin.tar.gz");
        pack(&darwin_tree, &darwin_tar);
        let darwin_out = temp.0.join("darwin-out");
        fs::create_dir_all(&darwin_out).unwrap();
        extract_otp_archive(&darwin_tar, &darwin_out, DARWIN).unwrap();
        assert!(darwin_out.join("bin/erl").is_file());
    }

    // ---- install recipe (fake Install, real production code path) --------

    const ERTS: &str = "17.0.5";

    /// Faithful miniature of the artifact's Install: same argument parsing,
    /// same -cross semantics (ERL_ROOT=`pwd`, TARGET_ERL_ROOT=<arg>), same
    /// sed templating and generated file set. `extra` runs before exit.
    fn fake_install(extra: &str) -> String {
        format!(
            r#"#!/bin/sh
# fake OTP Install (test double)
start_option=query
unset cross
while [ $# -ne 0 ]; do
  case $1 in
    -minimal) start_option=minimal ;;
    -sasl)    start_option=sasl ;;
    -cross)   cross=yes ;;
    *)        ERL_ROOT=$1 ;;
  esac
  shift
done
if [ -z "$cross" ]; then TARGET_ERL_ROOT="$ERL_ROOT"; else TARGET_ERL_ROOT="$ERL_ROOT"; ERL_ROOT=`pwd`; fi
[ -n "$ERL_ROOT" ] && [ -d "$ERL_ROOT" ] || exit 1
[ -d "$ERL_ROOT/erts-{ERTS}/bin" ] || exit 1
[ "$start_option" = minimal ] || {{ echo "would prompt" >&2; exit 4; }}
[ -d "$ERL_ROOT/bin" ] || mkdir "$ERL_ROOT/bin"
cd "$ERL_ROOT/erts-{ERTS}/bin"
sed -e "s;%FINAL_ROOTDIR%;$TARGET_ERL_ROOT;" erl.src > erl
chmod 755 erl
sed -e "s;%FINAL_ROOTDIR%;$TARGET_ERL_ROOT;" -e "s;%VSN%;{ERTS};" start.src > start
chmod 755 start
cd "$ERL_ROOT/bin"
for f in erl erlc erl_call dialyzer typer ct_run escript run_erl to_erl start; do
  cp -p "$ERL_ROOT/erts-{ERTS}/bin/$f" .
done
if [ -h epmd ]; then rm -f epmd; fi
ln -s ../erts-{ERTS}/bin/epmd epmd
sed -e "s;%EMU%;beam;" "$ERL_ROOT/erts-{ERTS}/bin/start_erl.src" > start_erl
chmod 755 start_erl
echo {ERTS} 29 > "$ERL_ROOT/releases/start_erl.data"
sed -e "s;%ERL_ROOT%/;;" "$ERL_ROOT/releases/RELEASES.src" > "$ERL_ROOT/releases/RELEASES"
cp -p ../releases/29/start_*.boot .
cp -p ../releases/29/no_dot_erlang.boot .
cp -p start_clean.boot start.boot
cp -p ../releases/29/start_clean.script start.script
{extra}
exit 0
"#
        )
    }

    /// Uninstalled make-release tree with the same entries the recipe
    /// validates in the real artifact.
    fn fake_release_tree(otp_root: &Path, install_script: &str) {
        let erts_bin = otp_root.join(format!("erts-{ERTS}/bin"));
        fs::create_dir_all(&erts_bin).unwrap();
        fs::write(otp_root.join("Install"), install_script).unwrap();
        fs::set_permissions(otp_root.join("Install"), fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(
            erts_bin.join("erl.src"),
            "#!/bin/sh\nROOTDIR=$(find_rootdir \"$0\" \"%FINAL_ROOTDIR%\")\nBINDIR=\"$ROOTDIR/erts-17.0.5/bin\"\nexec \"$BINDIR/erlexec\" ${1+\"$@\"}\n",
        )
        .unwrap();
        fs::write(
            erts_bin.join("start.src"),
            "#!/bin/sh\nROOTDIR=$(find_rootdir \"$0\" \"%FINAL_ROOTDIR%\")\nVSN=%VSN%\n",
        )
        .unwrap();
        fs::write(erts_bin.join("start_erl.src"), "#!/bin/sh\nEMU=%EMU%\n").unwrap();
        for elf in [
            "beam.smp", "erlexec", "epmd", "erlc", "erl_call", "dialyzer", "typer", "ct_run",
            "escript", "run_erl", "to_erl",
        ] {
            // Binary-looking payload: NUL bytes, no prefix.
            fs::write(erts_bin.join(elf), format!("\x7fELF\0\0{elf}\0")).unwrap();
            fs::set_permissions(erts_bin.join(elf), fs::Permissions::from_mode(0o755)).unwrap();
        }
        fs::create_dir_all(otp_root.join("lib/kernel-11.0.3/ebin")).unwrap();
        fs::write(
            otp_root.join("lib/kernel-11.0.3/ebin/kernel.app"),
            "{application,kernel,[]}.\n",
        )
        .unwrap();
        let rel = otp_root.join("releases/29");
        fs::create_dir_all(&rel).unwrap();
        fs::write(rel.join("OTP_VERSION"), "29.0.5\n").unwrap();
        for boot in [
            "start_clean.boot",
            "start_sasl.boot",
            "no_dot_erlang.boot",
            "start.boot",
        ] {
            fs::write(rel.join(boot), b"\x83boot\0").unwrap();
        }
        fs::write(
            rel.join("start_clean.script"),
            "%% script\n{script,{\"Erlang/OTP\",\"29\"},[]}.\n",
        )
        .unwrap();
        fs::write(
            otp_root.join("releases/RELEASES.src"),
            "[{release,\"Erlang/OTP\",\"29\",\"17.0.5\",[{kernel,\"11.0.3\",\"%ERL_ROOT%/lib/kernel-11.0.3\"}],permanent}].\n",
        )
        .unwrap();
    }

    /// Production-shaped layout: staging under <store>/tmp/stage-*/otp,
    /// final under <store>/objects/<id>/otp. The store root has a space.
    struct Fixture {
        _temp: TempDir,
        otp_root: PathBuf,
        final_root: PathBuf,
        scratch: PathBuf,
    }

    fn fixture(tag: &str, install_script: &str) -> Fixture {
        let temp = TempDir::named(tag);
        let store = temp.0.join("store root");
        let otp_root = store.join("tmp/stage-1/otp");
        let scratch = store.join("tmp/stage-2");
        fs::create_dir_all(&scratch).unwrap();
        fake_release_tree(&otp_root, install_script);
        let final_root = store.join("objects/abc-beam-29.0.5-elixir1.20.4/otp");
        Fixture {
            _temp: temp,
            otp_root,
            final_root,
            scratch,
        }
    }

    #[test]
    fn install_spec_has_cross_minimal_argv_cwd_and_writes() {
        let fx = fixture("spec", &fake_install(""));
        let spec = otp_install_spec(&fx.otp_root, &fx.final_root, &fx.scratch).unwrap();
        assert_eq!(
            spec.argv,
            vec![
                "/bin/sh".to_string(),
                fx.otp_root.join("Install").display().to_string(),
                "-cross".to_string(),
                "-minimal".to_string(),
                fx.final_root.display().to_string(),
            ]
        );
        assert_eq!(spec.cwd, fx.otp_root);
        assert_eq!(spec.write, vec![fx.otp_root.clone()]);
        assert_eq!(spec.scratch, fx.scratch);
        assert!(spec.env.is_empty());
        assert_eq!(spec.path, "/usr/bin:/bin");
        assert!(spec.argv[4].contains("store root"), "spaces are embeddable");
        // Characters Install's unescaped sed/sh templating cannot carry.
        for bad in [
            "/a;b",
            "/a&b",
            "/a\\b",
            "/a\nb",
            "/a\"b",
            "/a$b",
            "relative/otp",
        ] {
            assert!(
                otp_install_spec(&fx.otp_root, Path::new(bad), &fx.scratch).is_err(),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn pre_install_layout_is_validated_without_bin_erl() {
        let fx = fixture("pre", &fake_install(""));
        let layout = validate_otp_pre_install(&fx.otp_root, OTP_VERSION).unwrap();
        assert_eq!(layout.erts_vsn, ERTS);
        assert_eq!(layout.erts_dir, fx.otp_root.join(format!("erts-{ERTS}")));
        assert!(!fx.otp_root.join("bin/erl").exists());
        // bin/erl is a POST-install requirement.
        let e = verify_otp_install(&fx.otp_root, &fx.final_root, &layout).unwrap_err();
        assert!(e.to_string().contains("bin"), "{e}");
        // Missing template inputs are contextual failures.
        fs::remove_file(fx.otp_root.join("releases/RELEASES.src")).unwrap();
        let e = validate_otp_pre_install(&fx.otp_root, OTP_VERSION).unwrap_err();
        assert!(e.to_string().contains("RELEASES.src"), "{e}");
        // An Install without -cross is not this recipe's artifact.
        let fx2 = fixture(
            "pre2",
            "#!/bin/sh\nTARGET_ERL_ROOT=x %FINAL_ROOTDIR% -minimal)\n",
        );
        let e = validate_otp_pre_install(&fx2.otp_root, OTP_VERSION).unwrap_err();
        assert!(e.to_string().contains("-cross"), "{e}");
        // An already-installed tree is rejected as pre-install input.
        let fx3 = fixture("pre3", &fake_install(""));
        fs::create_dir_all(fx3.otp_root.join("bin")).unwrap();
        fs::write(fx3.otp_root.join("bin/erl"), "x").unwrap();
        assert!(validate_otp_pre_install(&fx3.otp_root, OTP_VERSION).is_err());
    }

    #[test]
    fn cross_install_embeds_final_prefix_and_leaves_no_staging_prefix() {
        let fx = fixture("cross", &fake_install(""));
        let layout = validate_otp_pre_install(&fx.otp_root, OTP_VERSION).unwrap();
        run_otp_install_with(
            &fx.otp_root,
            &fx.final_root,
            &fx.scratch,
            run_installer_spec,
        )
        .unwrap();
        verify_otp_install(&fx.otp_root, &fx.final_root, &layout).unwrap();

        let final_prefix = fx.final_root.to_str().unwrap();
        let staging_dir = fx.otp_root.parent().unwrap().to_str().unwrap();
        for launcher in prefix_bearing_launchers(&fx.otp_root, &layout) {
            let text = fs::read_to_string(&launcher).unwrap();
            assert!(
                text.contains(&format!("\"{final_prefix}\"")),
                "{}: {text}",
                launcher.display()
            );
            assert!(!text.contains(staging_dir), "{}", launcher.display());
            assert!(!text.contains("%FINAL_ROOTDIR%"));
            assert_eq!(mode_of(&launcher).unwrap(), 0o755, "{}", launcher.display());
        }
        assert!(!fs::read_to_string(fx.otp_root.join("bin/start"))
            .unwrap()
            .contains("%VSN%"));
        assert_eq!(
            fs::read_to_string(fx.otp_root.join("releases/start_erl.data")).unwrap(),
            "17.0.5 29\n"
        );
        let releases = fs::read_to_string(fx.otp_root.join("releases/RELEASES")).unwrap();
        assert!(releases.contains("\"lib/kernel-11.0.3\""), "{releases}");
        assert!(!releases.contains(staging_dir));
        assert_eq!(
            fs::read_link(fx.otp_root.join("bin/epmd")).unwrap(),
            PathBuf::from("../erts-17.0.5/bin/epmd")
        );
        // Copied ELF payloads are byte-identical and keep their mode.
        assert_eq!(
            fs::read(fx.otp_root.join("bin/erlc")).unwrap(),
            fs::read(fx.otp_root.join("erts-17.0.5/bin/erlc")).unwrap()
        );
        assert_eq!(mode_of(&fx.otp_root.join("bin/erlc")).unwrap(), 0o755);
        // Whole-tree scan is clean for the staging dir and the staged otp root.
        scan_tree(&fx.otp_root, staging_dir.as_bytes()).unwrap();
        scan_tree(&fx.otp_root, path_bytes(&fx.otp_root)).unwrap();
    }

    #[test]
    fn install_that_embeds_staging_prefix_is_rejected() {
        // A hypothetical Install that bakes the physical root into a launcher.
        let leaky = fake_install("echo \"# built in $ERL_ROOT\" >> \"$ERL_ROOT/bin/erl\"");
        let fx = fixture("leak", &leaky);
        let layout = validate_otp_pre_install(&fx.otp_root, OTP_VERSION).unwrap();
        run_otp_install_with(
            &fx.otp_root,
            &fx.final_root,
            &fx.scratch,
            run_installer_spec,
        )
        .unwrap();
        let e = verify_otp_install(&fx.otp_root, &fx.final_root, &layout).unwrap_err();
        assert!(e.to_string().contains("staging directory"), "{e}");
        assert!(e.to_string().contains("bin/erl"), "{e}");

        // ...or into a symlink target.
        let fx = fixture(
            "leaklink",
            &fake_install("ln -s \"$ERL_ROOT/erts-17.0.5/bin/heart\" \"$ERL_ROOT/bin/heart\""),
        );
        let layout = validate_otp_pre_install(&fx.otp_root, OTP_VERSION).unwrap();
        run_otp_install_with(
            &fx.otp_root,
            &fx.final_root,
            &fx.scratch,
            run_installer_spec,
        )
        .unwrap();
        let e = verify_otp_install(&fx.otp_root, &fx.final_root, &layout).unwrap_err();
        assert!(e.to_string().contains("symlink"), "{e}");

        // A symlink escaping the tree is rejected even without the prefix.
        let fx = fixture(
            "escape",
            &fake_install("ln -s /etc/passwd \"$ERL_ROOT/bin/escape\""),
        );
        let layout = validate_otp_pre_install(&fx.otp_root, OTP_VERSION).unwrap();
        run_otp_install_with(
            &fx.otp_root,
            &fx.final_root,
            &fx.scratch,
            run_installer_spec,
        )
        .unwrap();
        let e = verify_otp_install(&fx.otp_root, &fx.final_root, &layout).unwrap_err();
        assert!(e.to_string().contains("does not resolve inside"), "{e}");

        // Wrong embedded prefix (as if -cross were dropped) is caught too.
        let fx = fixture("nocross", &fake_install(""));
        let layout = validate_otp_pre_install(&fx.otp_root, OTP_VERSION).unwrap();
        let elsewhere = fx
            .final_root
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("other/otp");
        run_otp_install_with(&fx.otp_root, &elsewhere, &fx.scratch, run_installer_spec).unwrap();
        let e = verify_otp_install(&fx.otp_root, &fx.final_root, &layout).unwrap_err();
        assert!(
            e.to_string().contains("does not embed the final prefix"),
            "{e}"
        );
    }

    #[test]
    fn install_failures_propagate_with_context() {
        // Nonzero exit from the real runner: status and stderr surface.
        let fx = fixture("fail", "#!/bin/sh\n# TARGET_ERL_ROOT %FINAL_ROOTDIR% -cross) -minimal)\necho boom >&2\nexit 7\n");
        validate_otp_pre_install(&fx.otp_root, OTP_VERSION).unwrap();
        let e = run_otp_install_with(
            &fx.otp_root,
            &fx.final_root,
            &fx.scratch,
            run_installer_spec,
        )
        .unwrap_err();
        let text = e.to_string();
        assert!(text.contains("Install -cross -minimal failed"), "{text}");
        assert!(text.contains("7") && text.contains("boom"), "{text}");
        assert!(!fx.otp_root.join("bin/erl").exists());

        // Injected runner errors keep their kind (Unsupported from a future
        // sandbox backend must not be laundered into InvalidData).
        let e = run_otp_install_with(&fx.otp_root, &fx.final_root, &fx.scratch, |spec| {
            assert_eq!(spec.argv[2], "-cross");
            Err(io::Error::new(io::ErrorKind::Unsupported, "no sandbox"))
        })
        .unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::Unsupported);
        assert!(e.to_string().contains("no sandbox"));

        // Runner never invoked when the final prefix is not embeddable.
        let e = run_otp_install_with(&fx.otp_root, Path::new("/a;b"), &fx.scratch, |_| {
            panic!("runner must not run")
        })
        .unwrap_err();
        assert!(e.to_string().contains("cannot embed"), "{e}");

        // Real runner: the script prompts without -minimal -> stdin is
        // closed, it exits nonzero instead of hanging.
        let fx = fixture("prompt", &fake_install(""));
        let mut spec = otp_install_spec(&fx.otp_root, &fx.final_root, &fx.scratch).unwrap();
        spec.argv.retain(|a| a != "-minimal");
        let e = run_installer_spec(&spec).unwrap_err();
        assert!(e.to_string().contains("would prompt"), "{e}");
    }

    // ---- existing guards -------------------------------------------------

    #[test]
    fn plan_validation_rejects_hostile_fields() {
        let base = HexDep {
            app: "jason".into(),
            package: "jason".into(),
            version: "1.4.5".into(),
            inner_sha256: "a".repeat(64),
            outer_sha256: "b".repeat(64),
            managers: vec!["mix".into()],
        };
        let ok = ElixirPlan {
            otp_version: OTP_VERSION.into(),
            elixir_version: ELIXIR_VERSION.into(),
            deps: vec![base.clone()],
        };
        assert!(validate_plan(&ok).is_ok());
        for (field, value) in [
            ("app", "../evil"),
            ("app", "Evil"),
            ("version", "1.0/.."),
            ("outer", "zz"),
        ] {
            let mut bad = base.clone();
            match field {
                "app" => bad.app = value.into(),
                "version" => bad.version = value.into(),
                _ => bad.outer_sha256 = value.into(),
            }
            assert!(
                validate_plan(&ElixirPlan {
                    deps: vec![bad],
                    ..ok.clone()
                })
                .is_err(),
                "{field}={value}"
            );
        }
        let dup = ElixirPlan {
            deps: vec![base.clone(), base.clone()],
            ..ok.clone()
        };
        assert!(validate_plan(&dup).is_err());
        let mut manager = base.clone();
        manager.managers = vec!["curl".into()];
        assert!(validate_plan(&ElixirPlan {
            deps: vec![manager],
            ..ok.clone()
        })
        .is_err());
    }

    #[test]
    fn env_scrub_covers_beam_doors() {
        for p in ["MIX_", "HEX_", "REBAR_", "ERL_", "ELIXIR_"] {
            assert!(ENV_REMOVE_PREFIXES.contains(&p), "{p}");
        }
        let env = forced_env(Path::new("/b"), Path::new("/d"), Path::new("/s"));
        let mut keys: Vec<&str> = env.iter().map(|(k, _)| k.as_str()).collect();
        // The host-local tripwire checks the hexmark run against its own
        // copy of this list.
        let mut checked = crate::kernel::resolve::tripwire::ELIXIR_FORCED.to_vec();
        keys.sort_unstable();
        checked.sort_unstable();
        assert_eq!(keys, checked);
        for k in [
            "MIX_DEPS_PATH",
            "MIX_ARCHIVES",
            "MIX_REBAR3",
            "HEX_OFFLINE",
            "MIX_TARGET",
        ] {
            assert!(keys.contains(&k), "{k}");
        }
    }

    #[test]
    fn build_root_is_beam_qualified() {
        let spec = pin_spec(DARWIN);
        let root = build_root_at(Path::new("/p"), &beam_fingerprint_for(&spec));
        assert!(root.display().to_string().contains("_build/tog-"));
        assert_eq!(beam_fingerprint_for(&spec).len(), 16);
        // Both routes to the build root agree for the shipped selection.
        assert_eq!(
            build_root(DARWIN, Path::new("/p"), &shipped_selection().unwrap()).unwrap(),
            root
        );
    }

    /// The selection is the only authority on the sync path, so the object
    /// it realizes must have the id the pin tables realized before selection
    /// existed, on both platforms: that is the id every cached BEAM already
    /// has. If this drifts, every cached BEAM is orphaned.
    #[test]
    fn a_selected_row_and_the_pins_build_the_same_identity() {
        let selected = shipped_selection().unwrap();
        let root = Path::new("/srv/tog/store");
        for platform in Platform::ALL {
            let from_lock = beam_spec(*platform, &selected).unwrap();
            let from_pin = pin_spec(*platform);
            assert_eq!(from_lock.otp_version, from_pin.otp_version);
            assert_eq!(from_lock.otp_url, from_pin.otp_url);
            assert_eq!(from_lock.otp_sha256, from_pin.otp_sha256);
            assert_eq!(from_lock.elixir_sha256, from_pin.elixir_sha256);
            assert_eq!(from_lock.hex_sha512, from_pin.hex_sha512);
            assert_eq!(from_lock.rebar3_sha512, from_pin.rebar3_sha512);
            assert_eq!(
                beam_identity(&from_lock, root).unwrap().object_id(),
                beam_identity(&from_pin, root).unwrap().object_id(),
                "{}",
                platform.triple()
            );
            assert_eq!(
                beam_fingerprint_for(&from_lock),
                beam_fingerprint_for(&from_pin)
            );
        }
    }

    #[test]
    fn an_unknown_recipe_and_a_foreign_selection_are_both_refused() {
        // The Linux OTP row's recipe is the relocation recipe: an unknown
        // one means an install procedure this tog does not implement.
        let mut selected = shipped_selection().unwrap();
        for row in &mut selected.bundle.artifacts {
            if row.component == "otp" {
                row.recipe = "otp-install-cross-minimal/99".into();
            }
        }
        let error = beam_spec(LINUX, &selected).unwrap_err().to_string();
        assert!(error.contains("otp-install-cross-minimal/99"), "{error}");
        assert!(error.contains("upgrade tog"), "{error}");

        // A platform-neutral row is refused the same way.
        let mut hex_moved = shipped_selection().unwrap();
        for row in &mut hex_moved.bundle.artifacts {
            if row.component == "hex" {
                row.recipe = "beam-toolchain/9".into();
            }
        }
        let error = beam_spec(LINUX, &hex_moved).unwrap_err().to_string();
        assert!(error.contains("beam-toolchain/9"), "{error}");

        let mut foreign = shipped_selection().unwrap();
        foreign.ecosystem = "ruby".into();
        let error = beam_spec(LINUX, &foreign).unwrap_err().to_string();
        assert!(error.contains("not elixir (otp)"), "{error}");

        // All four components are required; dropping one is a refusal that
        // names what is missing.
        let mut without_rebar = shipped_selection().unwrap();
        without_rebar
            .bundle
            .artifacts
            .retain(|row| row.component != "rebar3");
        let error = beam_spec(LINUX, &without_rebar).unwrap_err().to_string();
        assert!(error.contains("rebar3"), "{error}");
    }

    /// Every closure this tailor writes carries which bundle realized it and
    /// which store object that bundle became: `tog status` compares the one,
    /// `tog run` resolves the other, and `tog run` rebuilds the build root
    /// from the recorded fingerprint.
    #[test]
    fn the_closure_body_records_the_bundle_and_the_runtime_object() {
        let selected = shipped_selection().unwrap();
        let spec = beam_spec(LINUX, &selected).unwrap();
        let beam_obj = Path::new("/store/objects/abc-beam-29.0.5-elixir1.20.4");
        let plan = ElixirPlan {
            otp_version: OTP_VERSION.into(),
            elixir_version: ELIXIR_VERSION.into(),
            deps: Vec::new(),
        };
        let body = closure_body(
            beam_obj,
            Path::new("/store/objects/def-deps-0"),
            Path::new("/store/forests/aa/def-deps-0/hex-deps"),
            &plan,
            &"c".repeat(64),
            &spec,
            &selected,
        )
        .unwrap();
        assert_eq!(body["toolchain"]["ecosystem"], "elixir");
        assert_eq!(body["toolchain"]["bundle_id"], selected.bundle_id());
        assert_eq!(body["toolchain"]["versions"]["otp"], OTP_VERSION);
        assert_eq!(body["toolchain"]["versions"]["elixir"], ELIXIR_VERSION);
        assert_eq!(body["runtime_object"]["id"], "abc-beam-29.0.5-elixir1.20.4");
        // The runtime object is the BEAM the projection already records, and
        // every pre-existing key survives beside the record.
        assert_eq!(body["beam_object"]["id"], body["runtime_object"]["id"]);
        assert_eq!(body["deps_object"]["id"], "def-deps-0");
        assert_eq!(body["mix_lock_sha256"], "c".repeat(64));
        assert_eq!(body["mutable_state"], "unattested");
        assert_eq!(body["beam_fingerprint"], beam_fingerprint_for(&spec));
        assert_eq!(body["plan"]["otp_version"], OTP_VERSION);
    }

    /// The durable root/2 record `project_elixir_env` publishes names
    /// exactly the BEAM object, the deps object, and the writable deps
    /// forest it cloned: nothing inferred from the closure JSON, nothing
    /// missing.
    #[test]
    fn closure_refs_name_every_object_this_producer_created() {
        let _attribution_lock = crate::kernel::policy::attribution_test_lock();
        let mut attribution = crate::kernel::policy::Attribution::open("elixir").unwrap();
        let temp = TempDir::named("closure-refs");
        let store_root = temp.0.join("store");
        for sub in ["objects", "meta", "cache/sha256", "tmp", "roots", "forests"] {
            fs::create_dir_all(store_root.join(sub)).unwrap();
        }
        let store = Store::for_test(store_root.canonicalize().unwrap());
        let lease = store
            .activity(crate::kernel::activity::ActivityMode::Shared)
            .unwrap();
        let activity = &lease;
        let beam_id =
            store.publish_bare_test("beam", &format!("{OTP_VERSION}-elixir{ELIXIR_VERSION}"));
        let deps_id = store.publish_bare_with(
            &crate::kernel::types::Identity {
                kind: "test".into(),
                name: "deps".into(),
                version: "0".into(),
                inputs: Default::default(),
            },
            |deps| {
                fs::create_dir_all(deps.join("jason")).unwrap();
                fs::write(deps.join("jason/mix.exs"), "").unwrap();
            },
        );
        let project = temp.0.join("project");
        fs::create_dir_all(&project).unwrap();
        let plan = ElixirPlan {
            otp_version: OTP_VERSION.into(),
            elixir_version: ELIXIR_VERSION.into(),
            deps: Vec::new(),
        };
        let forest = project_elixir_env(
            activity,
            Platform::host().unwrap(),
            &crate::kernel::fsroot::ProjectRoot::open(&project).unwrap(),
            &store.object_path(&beam_id),
            &store.object_path(&deps_id),
            &plan,
            &"c".repeat(64),
            false,
            &shipped_selection().unwrap(),
            &mut attribution,
        )
        .unwrap();
        attribution.finish(true).unwrap();

        assert_eq!(
            forest,
            expected_projection(&store, &project, &store.object_path(&deps_id)).unwrap()
        );
        let roots = store.roots().unwrap();
        assert_eq!(roots.len(), 1, "no durable root record was published");
        let record = roots[0].record.as_ref().expect("root/2 record");
        assert_eq!(
            record.objects,
            std::collections::BTreeSet::from([beam_id, deps_id])
        );
        assert_eq!(
            record.projections,
            std::collections::BTreeSet::from([store
                .projection_ref(crate::kernel::store::ProjectionBase::Forests, &forest)
                .unwrap()])
        );

        // `gc --register` rebuilds the same record from this closure alone.
        drop(lease);
        let reimported = crate::kernel::store::reimport_root_for_test(&store, &project).unwrap();
        assert_eq!(reimported.objects, record.objects);
        assert_eq!(reimported.projections, record.projections);
    }

    /// A project renamed mid-sync with another project put at its path:
    /// the held root keeps reading the original mix.exs and mix.lock.
    #[test]
    fn held_root_reads_the_original_project_after_a_swap() {
        use crate::tailors::Tailor as _;
        let temp = TempDir::named("held-root");
        let project = temp.0.join("app");
        fs::create_dir_all(&project).unwrap();
        fs::write(project.join("mix.exs"), "defmodule App.MixProject do end\n").unwrap();
        fs::write(project.join("mix.lock"), "%{\"original\" => {}}\n").unwrap();
        let root = ProjectRoot::open(&project).unwrap();

        fs::rename(&project, temp.0.join("app-moved")).unwrap();
        fs::create_dir_all(&project).unwrap();
        fs::write(project.join("mix.lock"), "%{\"replacement\" => {}}\n").unwrap();

        assert_eq!(read_mix_lock(&root).unwrap(), "%{\"original\" => {}}\n");
        // The replacement has no mix.exs; the held original still does.
        assert!(tailor::Elixir.detect(&root).unwrap());
        assert!(!tailor::Elixir
            .detect(&ProjectRoot::open(&project).unwrap())
            .unwrap());
    }
}

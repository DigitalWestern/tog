//! The Elixir tailor: Mix/Hex ecosystem — AST-validated lockfile (never
//! eval'd), dual-checksum-verified hex tarballs, source-tree deps projected
//! copy-on-write, four-artifact BEAM toolchain.
//!
//! Sol review 6 shaped this: mix.lock is CODE (an Elixir term literal) and
//! Mix itself evals it, so blanket's planning parses it with a strict AST
//! grammar under the pinned toolchain (exact 8-field :hex tuples only —
//! atoms/strings/lists/tuples of literals, nothing callable); the Elixir
//! release zip has neither Hex nor rebar3, so both are separately pinned;
//! native deps (make/rebar3 ports) write INTO their source trees, so the
//! deps projection is a writable clonefile copy, recorded unattested.

use crate::fetch::{download_verified_digest_held, download_verified_held, Digest};
use crate::platform::{no_pin, Platform};
use crate::sandbox::{force_env, BuildSpec};
use crate::store::Store;
use crate::types::Identity;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

const OTP_VERSION: &str = "29.0.5";
// Linux relocation recipe revision: an identity input of the Linux toolchain
// object and of the Linux BEAM fingerprint. Bump it whenever the Install
// invocation, what gets embedded, or the verification changes, so hex-deps
// objects and `_build/blanket-*` roots re-derive. Darwin never sees it.
const LINUX_RELOCATION_SCHEMA: &str = "otp-install-cross-minimal/1";

struct OtpPin {
    platform: Platform,
    url: &'static str,
    sha256: &'static str,
}

const OTP_PINS: &[OtpPin] = &[
    // erlef/otp_builds: Install already run pre-packaging, bin/erl at the root.
    OtpPin {
        platform: Platform::Aarch64AppleDarwin,
        url: "https://github.com/erlef/otp_builds/releases/download/OTP-29.0.5/otp-aarch64-apple-darwin.tar.gz",
        sha256: "24b9e00da2b9ad25b1f182e2efd73ff316e46ec4b143c0cc3c69dbd27d5a594d",
    },
    // Our own source build (LINUX_PORT.md stage 4: hex.pm bob's Ubuntu build
    // needs OpenSSL SM4 symbols Fedora omits). A `make release` tree: root
    // entries ./Install ./bin ./erts-17.0.5 ./lib ./releases ./misc ./usr —
    // UNINSTALLED, bin/erl does not exist until Install runs. Provenance
    // manifest alongside the asset in the same release.
    OtpPin {
        platform: Platform::X86_64UnknownLinuxGnu,
        url: "https://github.com/DigitalWestern/blanket-toolchains/releases/download/otp-29.0.5-x86_64-unknown-linux-gnu-fedora44/OTP-29.0.5-x86_64-unknown-linux-gnu-fedora44.tar.gz",
        sha256: "18ae1abc8fd39306c502e9a7fd6885df3125f56d783cb577057ec29ad17d01c4",
    },
];

fn otp_pin(platform: Platform) -> io::Result<&'static OtpPin> {
    OTP_PINS
        .iter()
        .find(|pin| pin.platform == platform)
        .ok_or_else(|| no_pin("beam/otp", platform, "stage 4"))
}

pub fn preflight_platform(platform: Platform) -> io::Result<()> {
    crate::platform::require_host(platform, "BEAM toolchain", "stage 4")?;
    otp_pin(platform).map(|_| ())
}

fn beam_identity(pin: &OtpPin, store_root: &Path) -> io::Result<Identity> {
    beam_identity_with(pin, store_root, LINUX_RELOCATION_SCHEMA)
}

fn beam_identity_with(
    pin: &OtpPin,
    store_root: &Path,
    relocation_schema: &str,
) -> io::Result<Identity> {
    let mut inputs = BTreeMap::from([
        ("schema".to_string(), "beam-toolchain/1".to_string()),
        ("otp_sha256".to_string(), pin.sha256.to_string()),
        ("elixir_sha256".to_string(), ELIXIR_SHA256.to_string()),
        ("hex_sha512".to_string(), HEX_SHA512.to_string()),
        ("rebar3_sha512".to_string(), REBAR3_SHA512.to_string()),
        (
            "versions".to_string(),
            format!("hex{HEX_VERSION}:rebar{REBAR3_VERSION}"),
        ),
        ("platform".to_string(), pin.platform.triple().to_string()),
    ]);
    if !pin.platform.is_macos() {
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
        inputs.insert("relocation_schema".to_string(), relocation_schema.to_string());
        inputs.insert("store_root".to_string(), root.to_string());
    }
    Ok(Identity {
        kind: "beam".into(),
        name: "beam".into(),
        version: format!("{OTP_VERSION}-elixir{ELIXIR_VERSION}"),
        inputs,
    })
}

const ELIXIR_VERSION: &str = "1.20.4";
// Platform-neutral BEAM code, keyed to the OTP major.
const ELIXIR_URL: &str =
    "https://github.com/elixir-lang/elixir/releases/download/v1.20.4/elixir-otp-29.zip";
const ELIXIR_SHA256: &str = "7863c546cda13fecc949e562e326042451dacf8fd8698a36783cb71eeb223b46";

// Hex + rebar3 are NOT in the Elixir release; Mix normally downloads them
// ad hoc. Pinned from builds.hex.pm (sha512s from its install CSVs).
const HEX_VERSION: &str = "2.5.1";
// OTP-QUALIFIED build (installs/hex.csv row for elixir 1.20 / otp 29):
// the legacy un-qualified ez is compiled for old OTP and hangs on 29.
const HEX_URL: &str = "https://builds.hex.pm/installs/1.20.0/hex-2.5.1-otp-29.ez";
const HEX_SHA512: &str = "6629f4b4bb2e040326151ebb853aad065e342c65ad3a0f2a2674dcf7164eb4328d6c929513d7230309ad75042024e72bef0e0a51ebff373b4173d2746b1772b7";
const REBAR3_VERSION: &str = "3.25.1";
// OTP-qualified escript (installs/rebar.csv); no otp-29 build published
// yet — the otp-28 escript runs on the 29 VM (BEAM forward-compat).
const REBAR3_URL: &str = "https://builds.hex.pm/installs/1.18.4/rebar3-3.25.1-otp-28";
const REBAR3_SHA512: &str = "992fd755b7926fae455e5e07d9d195f4d3e7f181609eed1b9cabfe548624df10d148cd4b59bda40bebb185d3d68f9a9fd68a70b294101c8ad9cf0fadcc683d24";

fn err(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

/// A short fingerprint of the whole BEAM toolchain, used to qualify build
/// paths and identities (stale _build across toolchains is a real hazard).
pub fn beam_fingerprint(platform: Platform) -> io::Result<String> {
    Ok(beam_fingerprint_with(otp_pin(platform)?, LINUX_RELOCATION_SCHEMA))
}

fn beam_fingerprint_with(pin: &OtpPin, relocation_schema: &str) -> String {
    let joined = if pin.platform.is_macos() {
        // Darwin: byte-for-byte the pre-Linux formula (golden c35290f692496d51).
        format!("{}:{ELIXIR_SHA256}:{HEX_SHA512}:{REBAR3_SHA512}", pin.sha256)
    } else {
        format!(
            "{}:{ELIXIR_SHA256}:{HEX_SHA512}:{REBAR3_SHA512}:{relocation_schema}",
            pin.sha256
        )
    };
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
// being written and the prefix baked into text. Blanket stages under
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
fn validate_otp_pre_install(otp_root: &Path) -> io::Result<OtpLayout> {
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
    for needle in ["#!", "-cross)", "-minimal)", "TARGET_ERL_ROOT", "%FINAL_ROOTDIR%"] {
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
        .ok_or_else(|| err(format!("unexpected OTP erts directory {}", erts_dir.display())))?
        .to_string();
    let erts_bin = erts_dir.join("bin");
    require_directory(&erts_bin, "ERTS bin directory")?;
    for file in ["beam.smp", "erlexec", "epmd", "erl.src", "start.src", "start_erl.src"] {
        require_regular(&erts_bin.join(file), &format!("ERTS {file}"))?;
    }
    for file in INSTALL_COPIED_BIN
        .iter()
        .filter(|f| !f.ends_with(".boot") && !f.ends_with(".script"))
    {
        require_regular(&erts_bin.join(file), &format!("ERTS {file}"))?;
    }
    for (template, token) in [("erl.src", "%FINAL_ROOTDIR%"), ("start.src", "%FINAL_ROOTDIR%")] {
        if !read_text(&erts_bin.join(template), template)?.contains(token) {
            return Err(err(format!(
                "OTP {template} lacks the {token} template token; relocation recipe does not apply"
            )));
        }
    }

    require_directory(&otp_root.join("lib"), "library root")?;
    let release_dir = otp_root.join("releases/29");
    require_directory(&release_dir, "OTP 29 release directory")?;
    let version = read_text(&release_dir.join("OTP_VERSION"), "OTP version file")?;
    if version.trim() != OTP_VERSION {
        return Err(err(format!(
            "OTP version file says {:?}, expected {OTP_VERSION}",
            version.trim()
        )));
    }
    for file in ["start_clean.boot", "start_clean.script", "no_dot_erlang.boot", "start.boot"] {
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
    if let Some(bad) = text.chars().find(|c| matches!(c, ';' | '&' | '\\' | '\n' | '\r' | '"' | '$' | '`')) {
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
    })
}

/// Execute an installer spec as a direct child: cleared environment, the
/// spec's PATH/cwd/env, HOME and TMPDIR in scratch, stdin closed (a prompt
/// must fail, not hang). This is a verified-artifact unpack step — sed, cp,
/// ln, chmod over the staged tree, the same trust class as the tar/unzip
/// calls around it, not a project build — so it does not go through the
/// build sandbox (Unsupported on Linux until LINUX_PORT.md stage 3 lands).
/// Its result is checked by verify_otp_install, including a whole-tree scan
/// for the staging prefix and a runtime probe before anything is committed.
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
        return Err(err("OTP releases/RELEASES is not the installed release metadata"));
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
        require_regular(&otp_root.join("bin").join(file), &format!("installed bin/{file}"))?;
    }
    let epmd = otp_root.join("bin/epmd");
    let md = fs::symlink_metadata(&epmd)
        .map_err(|e| io::Error::new(e.kind(), format!("OTP epmd link missing: {e}")))?;
    if !md.file_type().is_symlink() {
        return Err(err(format!("OTP epmd at {} is not a symlink", epmd.display())));
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
fn probe_otp_runtime(otp_root: &Path, scratch: &Path) -> io::Result<()> {
    let output = Command::new(otp_root.join("bin/erl"))
        .args([
            "-noshell",
            "-eval",
            "ok = crypto:start(), \
             32 = byte_size(crypto:hash(sha256, <<\"blanket\">>)), \
             {ok, _} = application:ensure_all_started(ssl), \
             true = is_list(ssl:versions()), \
             io:format(\"~s~n~s~n\", [erlang:system_info(otp_release), code:root_dir()]), \
             halt(0).",
        ])
        .current_dir(scratch)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", scratch)
        .env("TMPDIR", scratch)
        .env("LANG", "C")
        .stdin(std::process::Stdio::null())
        .output()
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
        return Err(err(format!("staged OTP reports release {release:?}, expected 29")));
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

fn extract_otp_archive(archive: &Path, destination: &Path, platform: Platform) -> io::Result<()> {
    let mut command = Command::new("/usr/bin/tar");
    command.arg("-xzf").arg(archive).arg("-C").arg(destination);
    let strip = otp_strip_components(platform);
    if strip > 0 {
        command.arg(format!("--strip-components={strip}"));
    }
    let status = command.status()?;
    if !status.success() {
        return Err(err(format!(
            "OTP extraction failed ({status}) for {} into {}",
            archive.display(),
            destination.display()
        )));
    }
    Ok(())
}

/// Ensure the composite BEAM toolchain object: otp/ + elixir/ (separate
/// roots, per Sol — never merge their trees) + archives/ (unpacked Hex) +
/// rebar3 escript.
pub fn ensure_beam(store: &Store) -> io::Result<PathBuf> {
    ensure_beam_for(store, Platform::host()?)
}

pub fn ensure_beam_for(store: &Store, platform: Platform) -> io::Result<PathBuf> {
    crate::platform::require_host(platform, "BEAM toolchain", "stage 4")?;
    let pin = otp_pin(platform)?;
    let identity = beam_identity(pin, &store.root)?;
    let id = identity.object_id();
    if store.has(&id) {
        crate::policy::check_cached(store, &id)?;
        return Ok(store.object_path(&id));
    }
    let otp_tar = download_verified_held(store, pin.url, pin.sha256)?;
    let elixir_zip = download_verified_held(store, ELIXIR_URL, ELIXIR_SHA256)?;
    let hex_ez = download_verified_digest_held(store, HEX_URL, &Digest::sha512(HEX_SHA512)?)?;
    let rebar3 = download_verified_digest_held(store, REBAR3_URL, &Digest::sha512(REBAR3_SHA512)?)?;

    let staged = store.stage()?;
    let result = (|| {
        let otp_root = staged.join("otp");
        fs::create_dir_all(&otp_root)?;
        extract_otp_archive(&otp_tar, &otp_root, platform)?;
        if platform.is_macos() {
            if !otp_root.join("bin/erl").is_file() {
                return Err(err("OTP extraction failed or has unexpected layout"));
            }
        } else {
            // Uninstalled make-release tree: run Install against the FINAL
            // object path (known from the identity) while writing into
            // staging, then prove the result before the ordinary commit.
            let layout = validate_otp_pre_install(&otp_root)?;
            let final_root = store.object_path(&id).join("otp");
            let scratch = store.stage()?;
            let installed =
                run_otp_install_with(&otp_root, &final_root, &scratch, run_installer_spec)
                    .and_then(|()| verify_otp_install(&otp_root, &final_root, &layout))
                    .and_then(|()| probe_otp_runtime(&otp_root, &scratch));
            let _ = crate::store::remove_tree(&scratch);
            installed?;
        }

        fs::create_dir_all(staged.join("elixir"))?;
        let st = Command::new("/usr/bin/unzip")
            .args(["-oq"])
            .arg(&elixir_zip)
            .args(["-d"])
            .arg(staged.join("elixir"))
            .status()?;
        if !st.success() || !staged.join("elixir/bin/mix").is_file() {
            return Err(err("Elixir extraction failed or has unexpected layout"));
        }
        // Hex archive: MIX_ARCHIVES holds unpacked .ez dirs (ez root is
        // hex-<ver>/). Unzip preserves that root.
        fs::create_dir_all(staged.join("archives"))?;
        let st = Command::new("/usr/bin/unzip")
            .args(["-oq"])
            .arg(&hex_ez)
            .args(["-d"])
            .arg(staged.join(format!("archives/hex-{HEX_VERSION}")))
            .status()?;
        if !st.success() {
            return Err(err("Hex archive extraction failed"));
        }
        fs::copy(&rebar3, staged.join("rebar3"))?;
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(staged.join("rebar3"), fs::Permissions::from_mode(0o755))?;
        }
        store.commit(&identity, &staged, &[]).map(|(path, _)| path)
    })();
    if result.is_err() {
        let _ = crate::store::remove_tree(&staged);
    }
    result
}

/// The forced environment for every blanket-controlled mix/elixir run
/// (Sol's door list: ERL_LIBS-class vars inject code paths or emulator
/// args before Mix's own controls apply).
const ENV_REMOVE_PREFIXES: &[&str] = &["MIX_", "HEX_", "REBAR_", "ERL_", "ELIXIR_"];
const ENV_REMOVE: &[&str] = &["ERTS_BIN", "RUN_ERL_PIPE", "RUN_ERL_LOG", "ERLC_USE_SERVER"];

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

/// Env for `blanket run` (MIX_ENV passes through from the user's shell —
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

/// Run the store mix for a delegated edit (`blanket update`).
pub(crate) fn run_checked(
    beam_obj: &Path,
    cwd: &Path,
    scratch: &Path,
    offline: bool,
    args: &[&str],
) -> io::Result<()> {
    crate::ui::trace(&format!("run: {} (in {})", args.join(" "), cwd.display()));
    let out = run_mix(beam_obj, cwd, scratch, offline, args)?;
    if crate::ui::verbose() {
        eprint!("{}", String::from_utf8_lossy(&out.stdout));
    }
    if !out.status.success() {
        return Err(io::Error::other(format!(
            "store {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(())
}

fn run_mix(
    beam_obj: &Path,
    cwd: &Path,
    scratch: &Path,
    offline: bool,
    args: &[&str],
) -> io::Result<std::process::Output> {
    let mut cmd = Command::new(beam_obj.join("elixir/bin").join(args[0]));
    cmd.args(&args[1..]).current_dir(cwd);
    cmd.env("PATH", beam_path(beam_obj));
    cmd.env("HOME", scratch);
    cmd.env("TMPDIR", scratch);
    let mut set = forced_env(beam_obj, &scratch.join("deps"), scratch);
    if !offline {
        set.retain(|(k, _)| k != "HEX_OFFLINE");
    }
    force_env(&mut cmd, ENV_REMOVE_PREFIXES, ENV_REMOVE, &set);
    cmd.stdin(std::process::Stdio::null());
    cmd.output()
        .map_err(|e| io::Error::new(e.kind(), format!("run store mix {args:?}: {e}")))
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
        // marker bytes: closed allowlist only (Sol review 6, finding 2).
        for m in &d.managers {
            if !matches!(m.as_str(), "mix" | "rebar3" | "rebar" | "make") {
                return Err(err(format!("{}: unsupported manager {m:?}", d.app)));
            }
        }
    }
    Ok(())
}

/// Plan: AST-parse mix.lock under the pinned toolchain (lock-only, no
/// eval); missing lock delegates `mix deps.get` (planner scratch, network).
pub fn plan_elixir(
    store: &Store,
    project_dir: &Path,
    beam_obj: &Path,
) -> io::Result<(ElixirPlan, String)> {
    if !project_dir.join("mix.exs").is_file() {
        return Err(err("mix.exs not found"));
    }
    let lock_path = project_dir.join("mix.lock");
    let scratch = store.stage()?;
    if !lock_path.is_file() {
        eprintln!("blanket: no mix.lock; resolving with the store mix (network, unsandboxed)...");
        let out = run_mix(beam_obj, project_dir, &scratch, false, &["mix", "deps.get"])?;
        if !out.status.success() {
            let _ = crate::store::remove_tree(&scratch);
            return Err(err(format!(
                "store mix deps.get failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
    } else {
        // Consistency gate for EXISTING locks: exit status only (this
        // evaluates mix.exs — delegated trust, never artifact authority).
        // Network-permitted (plan-phase doctrine): --check-locked needs
        // the hex registry; a persistent planner HEX_HOME keeps it warm.
        let planner_home = store.root.join("planner-hexhome");
        fs::create_dir_all(&planner_home)?;
        let out = run_mix(
            beam_obj,
            project_dir,
            &planner_home,
            false,
            &["mix", "deps.get", "--check-locked"],
        )?;
        if !out.status.success() {
            let _ = crate::store::remove_tree(&scratch);
            return Err(err(format!(
                "mix.exs and mix.lock are out of sync; run `blanket run mix \
                 deps.get` and retry\n{}",
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
    }
    let lock = fs::read_to_string(&lock_path)?;
    let helper = scratch.join("helper.exs");
    fs::write(&helper, HELPER)?;
    let out = run_mix(
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
            lock_path.to_str().ok_or_else(|| err("path not UTF-8"))?,
        ],
    )?;
    let _ = crate::store::remove_tree(&scratch);
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
        otp_version: OTP_VERSION.to_string(),
        elixir_version: ELIXIR_VERSION.to_string(),
        deps,
    };
    validate_plan(&plan)?;
    let now = fs::read_to_string(&lock_path)?;
    if now != lock {
        return Err(err("mix.lock changed while planning; re-run blanket sync"));
    }
    Ok((plan, hex::encode(Sha256::digest(lock.as_bytes()))))
}

/// Extraction containment: regular files and dirs, plus symlinks whose
/// target resolves INSIDE the dep dir (hex packages legitimately contain
/// safe symlinks — stricter-than-cargo here would be a regression).
fn check_dep_tree(dep_dir: &Path, app: &str) -> io::Result<()> {
    fn walk(root: &Path, dir: &Path, app: &str) -> io::Result<()> {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            let md = fs::symlink_metadata(&path)?;
            let ft = md.file_type();
            if ft.is_symlink() {
                let target = fs::read_link(&path)?;
                let resolved = path
                    .parent()
                    .map(|p| p.join(&target))
                    .and_then(|t| t.canonicalize().ok());
                let root_canon = root.canonicalize()?;
                let ok = resolved
                    .map(|c| c.starts_with(&root_canon))
                    .unwrap_or(false);
                if !ok {
                    return Err(err(format!("{app}: symlink escapes the package")));
                }
            } else if ft.is_dir() {
                walk(root, &path, app)?;
            } else if !ft.is_file() {
                return Err(err(format!("{app}: hostile special entry")));
            }
        }
        Ok(())
    }
    walk(dep_dir, dep_dir, app)
}

/// Realize the immutable deps-source object (kind "hex-deps"): every
/// tarball dual-checksum-verified by blanket (outer = sha256 of the .tar,
/// inner = sha256(VERSION ++ metadata.config ++ contents.tar.gz)).
pub fn realize_deps(
    store: &Store,
    platform: Platform,
    plan: &ElixirPlan,
    beam_obj: &Path,
) -> io::Result<PathBuf> {
    crate::platform::require_host(platform, "Hex dependencies", "stage 4")?;
    let _ = otp_pin(platform)?;
    validate_plan(plan)?;
    let mut inputs = BTreeMap::from([
        ("schema".to_string(), "hex-deps/1".to_string()),
        // .hex markers are generated under the pinned toolchain; their
        // bytes live in the object.
        ("beam".to_string(), beam_fingerprint(platform)?),
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
                // Managers shape the generated .hex marker bytes — they
                // are object-determining inputs (Sol review 6, finding 2).
                d.managers.join("+")
            ),
        );
    }
    let identity = Identity {
        kind: "hex-deps".into(),
        name: "deps".into(),
        version: plan.deps.len().to_string(),
        inputs,
    };
    let id = identity.object_id();
    if store.has(&id) {
        crate::policy::check_cached(store, &id)?;
        return Ok(store.object_path(&id));
    }

    let scratch = store.stage()?;
    let helper = scratch.join("helper.exs");
    fs::write(&helper, HELPER)?;
    let staged = store.stage()?;
    for d in &plan.deps {
        let url = format!(
            "https://repo.hex.pm/tarballs/{}-{}.tar",
            d.package, d.version
        );
        let tar = download_verified_held(store, &url, &d.outer_sha256).map_err(|e| {
            io::Error::new(e.kind(), format!("{}: {e}", d.app))
        })?;
        // Unpack the OUTER tar (VERSION, metadata.config, contents.tar.gz,
        // CHECKSUM) into scratch.
        let outer_dir = scratch.join(format!("outer-{}", d.app));
        fs::create_dir_all(&outer_dir)?;
        let st = Command::new("/usr/bin/tar")
            .args(["-xf"])
            .arg(&tar)
            .args(["-C"])
            .arg(&outer_dir)
            .status()?;
        if !st.success() {
            return Err(err(format!("{}: outer tar extraction failed", d.app)));
        }
        // Inner checksum per hex spec — over REGULAR outer members only.
        let mut hasher = Sha256::new();
        for part in ["VERSION", "metadata.config", "contents.tar.gz", "CHECKSUM"] {
            let p = outer_dir.join(part);
            let md = fs::symlink_metadata(&p)
                .map_err(|e| {
                    io::Error::new(
                        e.kind(),
                        format!("{}: missing {part} in tarball: {e}", d.app),
                    )
                })?;
            if !md.file_type().is_file() {
                return Err(err(format!("{}: {part} is not a regular file", d.app)));
            }
            if part != "CHECKSUM" {
                hasher.update(&fs::read(&p)?);
            }
        }
        let got_inner = hex::encode(hasher.finalize());
        if got_inner != d.inner_sha256 {
            return Err(err(format!(
                "{}: inner checksum mismatch\n  expected {}\n  got      {got_inner}",
                d.app, d.inner_sha256
            )));
        }
        // The tarball's own CHECKSUM member is the (deprecated) inner hash;
        // agreement is cheap belt-and-braces.
        let shipped = fs::read_to_string(outer_dir.join("CHECKSUM"))?;
        if !shipped.trim().eq_ignore_ascii_case(&d.inner_sha256) {
            return Err(err(format!(
                "{}: tarball CHECKSUM member disagrees with the lock",
                d.app
            )));
        }
        // Layout keyed by the lock APP name (may differ from package).
        let dep_dir = staged.join(&d.app);
        fs::create_dir_all(&dep_dir)?;
        let st = Command::new("/usr/bin/tar")
            .args(["-xzf"])
            .arg(outer_dir.join("contents.tar.gz"))
            .args(["-C"])
            .arg(&dep_dir)
            .status()?;
        if !st.success() {
            return Err(err(format!("{}: contents extraction failed", d.app)));
        }
        check_dep_tree(&dep_dir, &d.app)?;
        // Reserved destinations must not pre-exist in package contents —
        // a shipped symlink named .hex/hex_metadata.config would carry our
        // writes through the link (Sol review 6, finding 4).
        for reserved in [".hex", "hex_metadata.config"] {
            if fs::symlink_metadata(dep_dir.join(reserved)).is_ok() {
                return Err(err(format!(
                    "{}: package ships a reserved {reserved} entry; refusing",
                    d.app
                )));
            }
        }
        // Metadata cross-check: the app/version inside metadata.config must
        // agree with the lock coordinates.
        let meta = fs::read_to_string(outer_dir.join("metadata.config"))?;
        let has_kv = |k: &str, v: &str| meta.contains(&format!("{{<<\"{k}\">>,<<\"{v}\">>}}"));
        if !has_kv("app", &d.app) || !has_kv("version", &d.version) {
            return Err(err(format!(
                "{}: hex metadata disagrees with the lock (app/version)",
                d.app
            )));
        }
        fs::copy(
            outer_dir.join("metadata.config"),
            dep_dir.join("hex_metadata.config"),
        )?;
        // .hex marker via the pinned toolchain (ETF binary).
        let out = run_mix(
            beam_obj,
            &scratch,
            &scratch,
            true,
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
    let _ = crate::store::remove_tree(&scratch);
    store.commit(&identity, &staged, &[]).map(|(path, _)| path)
}

/// The ONE forest path a project's deps projection may live at: derived
/// from the canonical project dir and the deps object id, never from
/// closure-recorded strings (Sol review 6, finding 1).
pub fn expected_projection(
    store: &Store,
    project_dir: &Path,
    deps_obj: &Path,
) -> io::Result<PathBuf> {
    let home = store
        .root
        .parent()
        .ok_or_else(|| err("cannot locate blanket home"))?;
    let key =
        hex::encode(&Sha256::digest(project_dir.canonicalize()?.to_string_lossy().as_bytes())[..8]);
    let obj_id = deps_obj
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| err("deps object id not UTF-8"))?;
    Ok(home.join("forests").join(key).join(obj_id).join("hex-deps"))
}

/// Project: clonefile the deps object into a writable per-project tree
/// (native builds write into their source dirs — npm mutablePackages
/// precedent; recorded unattested) + closure envelope.
pub fn project_elixir_env(
    platform: Platform,
    project_dir: &Path,
    beam_obj: &Path,
    deps_obj: &Path,
    plan: &ElixirPlan,
    lock_sha256: &str,
    fresh: bool,
) -> io::Result<PathBuf> {
    let beam_obj = beam_obj.canonicalize()?;
    let deps_obj = deps_obj.canonicalize()?;
    let store = Store::open()?;
    let proj_dir = expected_projection(&store, project_dir, &deps_obj)?;
    if fresh && proj_dir.exists() {
        crate::store::remove_tree(&proj_dir)?;
    }
    if !proj_dir.exists() {
        // Atomic publication: clone into a tmp sibling, then rename — a
        // crashed clone must never be trusted as a complete forest.
        let parent = proj_dir.parent().unwrap();
        fs::create_dir_all(parent)?;
        let tmp = parent.join(format!(".hex-deps.tmp.{}", std::process::id()));
        if tmp.exists() {
            crate::store::remove_tree(&tmp)?;
        }
        crate::project::clone_tree_for(&deps_obj, &tmp, platform)?;
        fs::rename(&tmp, &proj_dir)?;
    }
    let object_ref = |path: &Path| -> io::Result<serde_json::Value> {
        let id = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| err(format!("object path has no UTF-8 id: {}", path.display())))?;
        Ok(serde_json::json!({"path": path.display().to_string(), "id": id}))
    };
    crate::project::write_closure(
        project_dir,
        "elixir",
        serde_json::json!({
            "beam_object": object_ref(&beam_obj)?,
            "deps_object": object_ref(&deps_obj)?,
            "deps_projection": proj_dir.display().to_string(),
            "mutable_state": "unattested",
            "mix_lock_sha256": lock_sha256,
            "beam_fingerprint": beam_fingerprint(platform)?,
            "plan": plan,
        }),
    )?;
    Ok(proj_dir)
}

/// Build root, qualified by the toolchain fingerprint (stale BEAM/native
/// artifacts across OTP/Elixir upgrades are a real hazard — Sol).
pub fn build_root(platform: Platform, project_dir: &Path) -> io::Result<PathBuf> {
    Ok(project_dir.join(format!(
        "_build/blanket-{}",
        beam_fingerprint(platform)?
    )))
}

/// Sandboxed `mix compile`: network denied, writes only the qualified
/// build root, the deps projection (native builds write in-tree), scratch.
pub fn build_sandboxed(
    platform: Platform,
    project_dir: &Path,
    beam_obj: &Path,
    deps_projection: &Path,
    args: &[String],
) -> io::Result<()> {
    for arg in args {
        let norm = arg.trim_start_matches('-');
        if norm.starts_with("deps-path") || norm.starts_with("build-path") {
            return Err(err(format!("{arg}: this flag is managed by blanket")));
        }
    }
    let project_dir = project_dir.canonicalize()?;
    let beam_obj = beam_obj.canonicalize()?;
    let deps_projection = deps_projection.canonicalize()?;
    let store = Store::open()?;
    let scratch = store.stage()?;
    let build = build_root(platform, &project_dir)?;
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
    };
    let result = crate::sandbox::run_build_spec_on(platform, &spec).map_err(|e| {
        io::Error::new(e.kind(), format!(
            "mix compile failed: {e}\n(network is denied during builds; deps \
             needing network at compile time or absent host libraries are \
             unsupported in v0)"
        ))
    });
    let _ = crate::store::remove_tree(&scratch);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    const DARWIN_OBJECT_ID: &str = "7859ae4c9aa35b6c24bd08c2ad7989ab13313a8b-beam-29.0.5-elixir1.20.4";
    const DARWIN_FINGERPRINT: &str = "c35290f692496d51";
    const LINUX: Platform = Platform::X86_64UnknownLinuxGnu;
    const DARWIN: Platform = Platform::Aarch64AppleDarwin;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "blanket-elixir-{tag}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path.canonicalize().unwrap())
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = crate::store::remove_tree(&self.0);
        }
    }

    // ---- pins / identity / fingerprint -----------------------------------

    #[test]
    fn darwin_identity_unchanged() {
        let pin = otp_pin(DARWIN).unwrap();
        let identity = beam_identity(pin, Path::new("/unused")).unwrap();
        assert_eq!(identity.object_id(), DARWIN_OBJECT_ID);
        assert_eq!(beam_fingerprint(DARWIN).unwrap(), DARWIN_FINGERPRINT);
        // Darwin inputs: exactly the pre-Linux set, no recipe/store-root keys.
        assert_eq!(identity.inputs.len(), 7);
        assert!(!identity.inputs.contains_key("relocation_schema"));
        assert!(!identity.inputs.contains_key("store_root"));
        // Neither the recipe revision nor the store root moves Darwin.
        let other_schema = beam_identity_with(pin, Path::new("/x"), "otp-install-cross-minimal/99").unwrap();
        assert_eq!(other_schema.object_id(), DARWIN_OBJECT_ID);
        assert_eq!(beam_fingerprint_with(pin, "otp-install-cross-minimal/99"), DARWIN_FINGERPRINT);
    }

    #[test]
    fn one_otp_row_per_platform_and_pins_exact() {
        for platform in Platform::ALL {
            let rows = OTP_PINS.iter().filter(|p| p.platform == *platform).count();
            assert_eq!(rows, 1, "{}", platform.triple());
        }
        assert_eq!(OTP_PINS.len(), Platform::ALL.len());
        assert_eq!(OTP_PINS[0].platform, DARWIN, "darwin row stays first");
        assert_eq!(
            OTP_PINS[0].url,
            "https://github.com/erlef/otp_builds/releases/download/OTP-29.0.5/otp-aarch64-apple-darwin.tar.gz"
        );
        assert_eq!(
            OTP_PINS[0].sha256,
            "24b9e00da2b9ad25b1f182e2efd73ff316e46ec4b143c0cc3c69dbd27d5a594d"
        );
        let linux = otp_pin(LINUX).unwrap();
        assert_eq!(
            linux.url,
            "https://github.com/DigitalWestern/blanket-toolchains/releases/download/otp-29.0.5-x86_64-unknown-linux-gnu-fedora44/OTP-29.0.5-x86_64-unknown-linux-gnu-fedora44.tar.gz"
        );
        assert_eq!(
            linux.sha256,
            "18ae1abc8fd39306c502e9a7fd6885df3125f56d783cb577057ec29ad17d01c4"
        );
        // Platform-neutral artifacts: untouched.
        assert_eq!(OTP_VERSION, "29.0.5");
        assert_eq!(ELIXIR_VERSION, "1.20.4");
        assert_eq!(
            ELIXIR_URL,
            "https://github.com/elixir-lang/elixir/releases/download/v1.20.4/elixir-otp-29.zip"
        );
        assert_eq!(
            ELIXIR_SHA256,
            "7863c546cda13fecc949e562e326042451dacf8fd8698a36783cb71eeb223b46"
        );
        assert_eq!(HEX_VERSION, "2.5.1");
        assert_eq!(HEX_URL, "https://builds.hex.pm/installs/1.20.0/hex-2.5.1-otp-29.ez");
        assert_eq!(HEX_SHA512, "6629f4b4bb2e040326151ebb853aad065e342c65ad3a0f2a2674dcf7164eb4328d6c929513d7230309ad75042024e72bef0e0a51ebff373b4173d2746b1772b7");
        assert_eq!(REBAR3_VERSION, "3.25.1");
        assert_eq!(REBAR3_URL, "https://builds.hex.pm/installs/1.18.4/rebar3-3.25.1-otp-28");
        assert_eq!(REBAR3_SHA512, "992fd755b7926fae455e5e07d9d195f4d3e7f181609eed1b9cabfe548624df10d148cd4b59bda40bebb185d3d68f9a9fd68a70b294101c8ad9cf0fadcc683d24");
        assert!(preflight_platform(Platform::host().unwrap()).is_ok());
    }

    #[test]
    fn linux_identity_is_separate_and_tracks_recipe_and_store_root() {
        let root = Path::new("/srv/blanket/store");
        let linux = beam_identity(otp_pin(LINUX).unwrap(), root).unwrap();
        let darwin = beam_identity(otp_pin(DARWIN).unwrap(), root).unwrap();
        assert_ne!(linux.object_id(), darwin.object_id());
        assert_eq!(linux.inputs["platform"], "x86_64-unknown-linux-gnu");
        assert_eq!(linux.inputs["relocation_schema"], LINUX_RELOCATION_SCHEMA);
        assert_eq!(linux.inputs["store_root"], "/srv/blanket/store");
        for key in ["otp_sha256", "elixir_sha256", "hex_sha512", "rebar3_sha512"] {
            assert!(linux.inputs.contains_key(key), "{key}");
        }
        assert_eq!(linux.inputs["otp_sha256"], otp_pin(LINUX).unwrap().sha256);
        // The object path itself is never an input (would be circular).
        assert!(!linux.inputs.values().any(|v| v.contains("/objects/")));

        let other_root = beam_identity(otp_pin(LINUX).unwrap(), Path::new("/other/store")).unwrap();
        assert_ne!(other_root.object_id(), linux.object_id());
        let other_schema =
            beam_identity_with(otp_pin(LINUX).unwrap(), root, "otp-install-cross-minimal/2").unwrap();
        assert_ne!(other_schema.object_id(), linux.object_id());
        assert!(beam_identity(otp_pin(LINUX).unwrap(), Path::new("relative")).is_err());
    }

    #[test]
    fn linux_fingerprint_and_build_root_track_recipe() {
        let linux = beam_fingerprint(LINUX).unwrap();
        assert_eq!(linux.len(), 16);
        assert_ne!(linux, DARWIN_FINGERPRINT);
        assert_ne!(
            beam_fingerprint_with(otp_pin(LINUX).unwrap(), "otp-install-cross-minimal/2"),
            linux
        );
        let linux_root = build_root(LINUX, Path::new("/p")).unwrap();
        let darwin_root = build_root(DARWIN, Path::new("/p")).unwrap();
        assert_eq!(linux_root, Path::new("/p").join(format!("_build/blanket-{linux}")));
        assert_eq!(
            darwin_root,
            Path::new("/p").join(format!("_build/blanket-{DARWIN_FINGERPRINT}"))
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
        let temp = TempDir::new("extract");
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
        assert!(!linux_out.join("bin/erl").exists(), "pre-install: no bin/erl yet");
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
        for elf in ["beam.smp", "erlexec", "epmd", "erlc", "erl_call", "dialyzer", "typer", "ct_run", "escript", "run_erl", "to_erl"] {
            // Binary-looking payload: NUL bytes, no prefix.
            fs::write(erts_bin.join(elf), format!("\x7fELF\0\0{elf}\0")).unwrap();
            fs::set_permissions(erts_bin.join(elf), fs::Permissions::from_mode(0o755)).unwrap();
        }
        fs::create_dir_all(otp_root.join("lib/kernel-11.0.3/ebin")).unwrap();
        fs::write(otp_root.join("lib/kernel-11.0.3/ebin/kernel.app"), "{application,kernel,[]}.\n").unwrap();
        let rel = otp_root.join("releases/29");
        fs::create_dir_all(&rel).unwrap();
        fs::write(rel.join("OTP_VERSION"), "29.0.5\n").unwrap();
        for boot in ["start_clean.boot", "start_sasl.boot", "no_dot_erlang.boot", "start.boot"] {
            fs::write(rel.join(boot), b"\x83boot\0").unwrap();
        }
        fs::write(rel.join("start_clean.script"), "%% script\n{script,{\"Erlang/OTP\",\"29\"},[]}.\n").unwrap();
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
        let temp = TempDir::new(tag);
        let store = temp.0.join("store root");
        let otp_root = store.join("tmp/stage-1/otp");
        let scratch = store.join("tmp/stage-2");
        fs::create_dir_all(&scratch).unwrap();
        fake_release_tree(&otp_root, install_script);
        let final_root = store.join("objects/abc-beam-29.0.5-elixir1.20.4/otp");
        Fixture { _temp: temp, otp_root, final_root, scratch }
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
        for bad in ["/a;b", "/a&b", "/a\\b", "/a\nb", "/a\"b", "/a$b", "relative/otp"] {
            assert!(
                otp_install_spec(&fx.otp_root, Path::new(bad), &fx.scratch).is_err(),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn pre_install_layout_is_validated_without_bin_erl() {
        let fx = fixture("pre", &fake_install(""));
        let layout = validate_otp_pre_install(&fx.otp_root).unwrap();
        assert_eq!(layout.erts_vsn, ERTS);
        assert_eq!(layout.erts_dir, fx.otp_root.join(format!("erts-{ERTS}")));
        assert!(!fx.otp_root.join("bin/erl").exists());
        // bin/erl is a POST-install requirement.
        let e = verify_otp_install(&fx.otp_root, &fx.final_root, &layout).unwrap_err();
        assert!(e.to_string().contains("bin"), "{e}");
        // Missing template inputs are contextual failures.
        fs::remove_file(fx.otp_root.join("releases/RELEASES.src")).unwrap();
        let e = validate_otp_pre_install(&fx.otp_root).unwrap_err();
        assert!(e.to_string().contains("RELEASES.src"), "{e}");
        // An Install without -cross is not this recipe's artifact.
        let fx2 = fixture("pre2", "#!/bin/sh\nTARGET_ERL_ROOT=x %FINAL_ROOTDIR% -minimal)\n");
        let e = validate_otp_pre_install(&fx2.otp_root).unwrap_err();
        assert!(e.to_string().contains("-cross"), "{e}");
        // An already-installed tree is rejected as pre-install input.
        let fx3 = fixture("pre3", &fake_install(""));
        fs::create_dir_all(fx3.otp_root.join("bin")).unwrap();
        fs::write(fx3.otp_root.join("bin/erl"), "x").unwrap();
        assert!(validate_otp_pre_install(&fx3.otp_root).is_err());
    }

    #[test]
    fn cross_install_embeds_final_prefix_and_leaves_no_staging_prefix() {
        let fx = fixture("cross", &fake_install(""));
        let layout = validate_otp_pre_install(&fx.otp_root).unwrap();
        run_otp_install_with(&fx.otp_root, &fx.final_root, &fx.scratch, run_installer_spec).unwrap();
        verify_otp_install(&fx.otp_root, &fx.final_root, &layout).unwrap();

        let final_prefix = fx.final_root.to_str().unwrap();
        let staging_dir = fx.otp_root.parent().unwrap().to_str().unwrap();
        for launcher in prefix_bearing_launchers(&fx.otp_root, &layout) {
            let text = fs::read_to_string(&launcher).unwrap();
            assert!(text.contains(&format!("\"{final_prefix}\"")), "{}: {text}", launcher.display());
            assert!(!text.contains(staging_dir), "{}", launcher.display());
            assert!(!text.contains("%FINAL_ROOTDIR%"));
            assert_eq!(mode_of(&launcher).unwrap(), 0o755, "{}", launcher.display());
        }
        assert!(!fs::read_to_string(fx.otp_root.join("bin/start")).unwrap().contains("%VSN%"));
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
        let layout = validate_otp_pre_install(&fx.otp_root).unwrap();
        run_otp_install_with(&fx.otp_root, &fx.final_root, &fx.scratch, run_installer_spec).unwrap();
        let e = verify_otp_install(&fx.otp_root, &fx.final_root, &layout).unwrap_err();
        assert!(e.to_string().contains("staging directory"), "{e}");
        assert!(e.to_string().contains("bin/erl"), "{e}");

        // ...or into a symlink target.
        let fx = fixture("leaklink", &fake_install("ln -s \"$ERL_ROOT/erts-17.0.5/bin/heart\" \"$ERL_ROOT/bin/heart\""));
        let layout = validate_otp_pre_install(&fx.otp_root).unwrap();
        run_otp_install_with(&fx.otp_root, &fx.final_root, &fx.scratch, run_installer_spec).unwrap();
        let e = verify_otp_install(&fx.otp_root, &fx.final_root, &layout).unwrap_err();
        assert!(e.to_string().contains("symlink"), "{e}");

        // A symlink escaping the tree is rejected even without the prefix.
        let fx = fixture("escape", &fake_install("ln -s /etc/passwd \"$ERL_ROOT/bin/escape\""));
        let layout = validate_otp_pre_install(&fx.otp_root).unwrap();
        run_otp_install_with(&fx.otp_root, &fx.final_root, &fx.scratch, run_installer_spec).unwrap();
        let e = verify_otp_install(&fx.otp_root, &fx.final_root, &layout).unwrap_err();
        assert!(e.to_string().contains("does not resolve inside"), "{e}");

        // Wrong embedded prefix (as if -cross were dropped) is caught too.
        let fx = fixture("nocross", &fake_install(""));
        let layout = validate_otp_pre_install(&fx.otp_root).unwrap();
        let elsewhere = fx.final_root.parent().unwrap().parent().unwrap().join("other/otp");
        run_otp_install_with(&fx.otp_root, &elsewhere, &fx.scratch, run_installer_spec).unwrap();
        let e = verify_otp_install(&fx.otp_root, &fx.final_root, &layout).unwrap_err();
        assert!(e.to_string().contains("does not embed the final prefix"), "{e}");
    }

    #[test]
    fn install_failures_propagate_with_context() {
        // Nonzero exit from the real runner: status and stderr surface.
        let fx = fixture("fail", "#!/bin/sh\n# TARGET_ERL_ROOT %FINAL_ROOTDIR% -cross) -minimal)\necho boom >&2\nexit 7\n");
        validate_otp_pre_install(&fx.otp_root).unwrap();
        let e = run_otp_install_with(&fx.otp_root, &fx.final_root, &fx.scratch, run_installer_spec).unwrap_err();
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
        assert!(validate_plan(&ElixirPlan { deps: vec![manager], ..ok.clone() }).is_err());
    }

    #[test]
    fn env_scrub_covers_beam_doors() {
        for p in ["MIX_", "HEX_", "REBAR_", "ERL_", "ELIXIR_"] {
            assert!(ENV_REMOVE_PREFIXES.contains(&p), "{p}");
        }
        let env = forced_env(Path::new("/b"), Path::new("/d"), Path::new("/s"));
        let keys: Vec<&str> = env.iter().map(|(k, _)| k.as_str()).collect();
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
        let root = build_root(Platform::Aarch64AppleDarwin, Path::new("/p")).unwrap();
        assert!(root.display().to_string().contains("_build/blanket-"));
        assert_eq!(beam_fingerprint(Platform::Aarch64AppleDarwin)
            .unwrap()
            .len(), 16);
    }
}

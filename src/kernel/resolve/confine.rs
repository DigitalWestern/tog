//! Confinement for resolution tools: the `Proxy` network mode of the
//! sandbox (kernel layer).
//!
//! A resolution tool (npm, cargo, uv, ...) is treated as able to run
//! project-chosen code, so it runs only isolated. On Linux the isolation is
//! bubblewrap with:
//!
//! - a private network namespace whose only way out is tog's proxy: the
//!   proxy's Unix socket is bound at `/run/tog/proxy.sock`, and the first
//!   process, `tog __resolution-relay`, listens on `127.0.0.1:8119` inside
//!   the namespace and splices each connection to that socket;
//! - the project as a staged snapshot bound at its real path (the real
//!   project is not mounted at all), store objects read-only, fresh `/tmp`
//!   and `/dev`, and no `/etc/resolv.conf`;
//! - every mounted root scanned for Unix sockets beforehand, and a seccomp
//!   filter in the tool's process that refuses to create one;
//! - an environment built from empty, with every program-naming setting a
//!   tool reads forced to a safe value (`forced_settings`).
//!
//! `confined_run` is the entry point: it picks the isolation tier, checks
//! the mounts, runs the relay under bubblewrap, and returns the tool's
//! status with the exec log. When it returns, no process of the tool's
//! tree is alive.

use crate::kernel::activity::StoreActivity;
use crate::kernel::resolve::relay::{self, RelayRecord, ToolStatus};
use crate::kernel::resolve::snapshot::{self, Snapshot};
use crate::kernel::sandbox;
use crate::kernel::store::{self, Store};
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{self, Read};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

// ---------------------------------------------------------------------------
// Isolation tiers

/// An engine that can isolate a resolution tool on this machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Engine {
    Bubblewrap,
}

impl Engine {
    pub fn name(self) -> &'static str {
        match self {
            Engine::Bubblewrap => "bubblewrap",
        }
    }
}

/// One engine that is usable here, and whether it can fence the network
/// to the proxy (the `confined` tier) or only isolate files and processes
/// (the `isolated` tier, which records `unconfined-resolution`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TierOffer {
    pub engine: Engine,
    pub fenced: bool,
}

impl TierOffer {
    /// The record's `isolation` field.
    pub fn isolation(self) -> &'static str {
        if self.fenced {
            "confined"
        } else {
            "isolated"
        }
    }

    /// The exception kinds a run in this tier records.
    pub fn exceptions(self) -> &'static [&'static str] {
        if self.fenced {
            &[]
        } else {
            &[crate::kernel::policy::UNCONFINED_RESOLUTION]
        }
    }
}

/// A capability this machine lacks, why, and how to get it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Missing {
    pub capability: &'static str,
    pub reason: String,
    pub fix: String,
}

/// Every engine this build of tog can try, probed: what is usable and
/// what is not.
pub fn probe_tiers(activity: &StoreActivity) -> (Vec<TierOffer>, Vec<Missing>) {
    let mut offers = Vec::new();
    let mut missing = Vec::new();
    match sandbox::bwrap_preflight_with_activity(Some(activity)) {
        Ok(_) => offers.push(TierOffer {
            engine: Engine::Bubblewrap,
            fenced: true,
        }),
        Err(error) => missing.push(Missing {
            capability: "bubblewrap",
            reason: error.to_string(),
            fix: "install bubblewrap and allow it unprivileged user namespaces".to_string(),
        }),
    }
    (offers, missing)
}

/// The isolation rule: the strongest offer wins; a fenced one always
/// beats an unfenced one. An unfenced offer is refused when policy denies
/// `unconfined-resolution`. With no usable offer, the refusal names the
/// tool, why it needs isolation, and every missing capability with its fix.
pub fn choose_tier(
    offers: &[TierOffer],
    missing: &[Missing],
    unconfined_denied: bool,
    tool: &str,
    why: &str,
) -> io::Result<TierOffer> {
    if let Some(offer) = offers.iter().find(|offer| offer.fenced) {
        return Ok(*offer);
    }
    let unfenced = offers.iter().find(|offer| !offer.fenced);
    if let (Some(offer), false) = (unfenced, unconfined_denied) {
        return Ok(*offer);
    }
    let mut message = format!("{tool} {why}, so it runs only in isolation, and ");
    match unfenced {
        Some(offer) => message.push_str(&format!(
            "the only isolation here ({}) cannot fence its network to tog's proxy, which \
             policy denies (unconfined-resolution)",
            offer.engine.name()
        )),
        None => message.push_str("this machine cannot isolate it"),
    }
    for gap in missing {
        message.push_str(&format!(
            ". {}: {} (fix: {})",
            gap.capability, gap.reason, gap.fix
        ));
    }
    message.push_str(
        ". This build of tog has no other isolation backend (no container engine or \
         isolation helper support), so enable one of the above and run the command again",
    );
    Err(io::Error::new(io::ErrorKind::Unsupported, message))
}

// ---------------------------------------------------------------------------
// Forced program settings

/// The store paths a tool's forced settings name.
#[derive(Clone, Debug, Default)]
pub struct ForcedInputs<'a> {
    /// The store git every tool that starts git is pointed at.
    pub git: Option<&'a Path>,
    /// The shell npm and pnpm run scripts with (scripts are also off).
    pub sh: Option<&'a Path>,
    /// The store Rust toolchain object (cargo's `rustc` and `rustdoc`).
    pub rust: Option<&'a Path>,
    /// The store Python (uv's `--python`).
    pub python: Option<&'a Path>,
    /// Every registry name cargo's configuration defines.
    pub cargo_registries: &'a [String],
}

/// The forced settings of one tool: arguments for the caller to place
/// where the tool reads them, variables to set, and variables that must be
/// absent.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Forced {
    pub args: Vec<OsString>,
    pub env: Vec<(OsString, OsString)>,
    pub unset: Vec<&'static str>,
}

impl Forced {
    /// Make `env` obey these settings: forced variables replace the
    /// caller's, and unset ones are removed.
    pub fn apply(&self, env: &mut Vec<(OsString, OsString)>) {
        env.retain(|(key, _)| {
            !self.unset.iter().any(|unset| key == OsStr::new(unset))
                && !self.env.iter().any(|(forced, _)| forced == key)
        });
        env.extend(self.env.iter().cloned());
    }
}

/// One tool row. Placeholders in `flags` are replaced from
/// `ForcedInputs`: `@GIT@`, `@SH@`, `@RUST@`, `@PYTHON@`, and
/// `@REGISTRY@` (the row's `per_registry` flags repeat once per cargo
/// registry).
struct ForcedRow {
    tool: &'static str,
    flags: &'static [&'static str],
    per_registry: &'static [&'static str],
    env: &'static [(&'static str, &'static str)],
    unset: &'static [&'static str],
}

/// The forced program settings, one row per tool. Each is proved by the
/// marker fixtures under `tests/fixtures/proxy/forced/<tool>/`.
const FORCED: &[ForcedRow] = &[
    ForcedRow {
        tool: "npm",
        flags: &[
            "--git=@GIT@",
            "--script-shell=@SH@",
            "--shell=@SH@",
            "--ignore-scripts",
            "--node-options=",
            "--node-gyp=/nonexistent/node-gyp",
            "--editor=false",
            "--browser=false",
            "--viewer=false",
        ],
        per_registry: &[],
        env: &[],
        unset: &["NODE_OPTIONS"],
    },
    ForcedRow {
        tool: "pnpm",
        flags: &[
            "--config.script-shell=@SH@",
            "--config.shell-emulator=false",
            "--config.git-shallow-hosts=",
            "--ignore-scripts",
            "--config.node-options=",
            "--config.pnpmfile=.pnpmfile.cjs",
            "--config.global-pnpmfile=",
            "--config.manage-package-manager-versions=false",
        ],
        per_registry: &[],
        env: &[],
        unset: &["NODE_OPTIONS"],
    },
    ForcedRow {
        tool: "cargo",
        flags: &[
            "--config",
            "build.rustc=\"@RUST@/bin/rustc\"",
            "--config",
            "build.rustc-wrapper=\"\"",
            "--config",
            "build.rustc-workspace-wrapper=\"\"",
            "--config",
            "build.rustdoc=\"@RUST@/bin/rustdoc\"",
            "--config",
            "registry.global-credential-providers=[\"cargo:token\"]",
            "--config",
            "net.git-fetch-with-cli=true",
        ],
        per_registry: &[
            "--config",
            "registries.@REGISTRY@.credential-provider=[\"cargo:token\"]",
        ],
        env: &[],
        unset: &[
            "RUSTC",
            "RUSTC_WRAPPER",
            "RUSTC_WORKSPACE_WRAPPER",
            "RUSTDOC",
            "CARGO_BUILD_RUSTC",
            "CARGO_BUILD_RUSTC_WRAPPER",
            "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
            "CARGO_BUILD_RUSTDOC",
            "CARGO_REGISTRY_GLOBAL_CREDENTIAL_PROVIDERS",
        ],
    },
    ForcedRow {
        tool: "uv",
        flags: &[
            "--keyring-provider",
            "disabled",
            "--no-python-downloads",
            "--no-config",
            "--python",
            "@PYTHON@",
        ],
        per_registry: &[],
        env: &[],
        unset: &["UV_PYTHON", "UV_KEYRING_PROVIDER", "UV_CONFIG_FILE"],
    },
    ForcedRow {
        tool: "git",
        flags: &[],
        per_registry: &[],
        env: &[],
        unset: &[],
    },
    ForcedRow {
        tool: "go",
        flags: &[],
        per_registry: &[],
        env: &[
            ("GOFLAGS", "-mod=mod"),
            ("GOTOOLCHAIN", "local"),
            ("GOVCS", "*:off"),
            ("GOENV", "off"),
            ("GOAUTH", "off"),
            ("CGO_ENABLED", "0"),
        ],
        unset: &[
            "GONOSUMDB",
            "GOPRIVATE",
            "GONOPROXY",
            "CC",
            "CXX",
            "GOCACHEPROG",
        ],
    },
    ForcedRow {
        tool: "bundler",
        flags: &[],
        per_registry: &[],
        env: &[("BUNDLE_IGNORE_CONFIG", "1")],
        unset: &["BUNDLE_GEMFILE", "BUNDLE_APP_CONFIG"],
    },
    ForcedRow {
        tool: "mix",
        flags: &[],
        per_registry: &[],
        env: &[],
        unset: &["MIX_EXS", "MIX_DEPS_PATH", "MIX_HOME", "MIX_ARCHIVES"],
    },
    ForcedRow {
        tool: "dotnet",
        flags: &["--disable-build-servers", "-maxcpucount:1"],
        per_registry: &[],
        env: &[
            ("DOTNET_CLI_TELEMETRY_OPTOUT", "1"),
            ("DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE", "1"),
            ("DOTNET_NOLOGO", "1"),
            ("DOTNET_EnableDiagnostics", "0"),
            ("MSBUILDDISABLENODEREUSE", "1"),
        ],
        unset: &[],
    },
];

/// git's forced settings, carried in `GIT_CONFIG_COUNT`/`KEY`/`VALUE`
/// because the tools, not tog, start git. Every tool gets them.
const GIT_FORCED: &[(&str, &str)] = &[
    ("credential.helper", ""),
    ("core.fsmonitor", "false"),
    ("core.hooksPath", "/dev/null"),
    ("core.sshCommand", "false"),
    ("core.askPass", "false"),
    ("core.gitProxy", ""),
    ("uploadpack.packObjectsHook", ""),
    ("protocol.allow", "never"),
    ("protocol.https.allow", "always"),
    ("protocol.file.allow", "always"),
    ("protocol.ext.allow", "never"),
    ("protocol.ssh.allow", "never"),
    ("protocol.git.allow", "never"),
    ("protocol.http.allow", "never"),
];

const GIT_ENV: &[(&str, &str)] = &[
    ("GIT_CONFIG_NOSYSTEM", "1"),
    ("GIT_CONFIG_GLOBAL", "/dev/null"),
    ("GIT_TERMINAL_PROMPT", "0"),
];

const GIT_UNSET: &[&str] = &[
    "GIT_SSH_COMMAND",
    "GIT_SSH",
    "GIT_ASKPASS",
    "SSH_ASKPASS",
    "GIT_PROXY_COMMAND",
    "GIT_EXEC_PATH",
    "GIT_CONFIG",
    "GIT_CONFIG_SYSTEM",
];

/// The tools with a forced-settings row.
pub fn forced_tools() -> impl Iterator<Item = &'static str> {
    FORCED.iter().map(|row| row.tool)
}

/// `tool`'s forced settings, git's included. `extra_git` are further git
/// settings the caller needs (`http.proxy`, `url.<base>.insteadOf`, ...);
/// they come first, so a forced setting always has the last word.
pub fn forced_settings(
    tool: &str,
    inputs: &ForcedInputs<'_>,
    extra_git: &[(String, String)],
) -> io::Result<Forced> {
    let row = FORCED.iter().find(|row| row.tool == tool).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{tool} has no forced-settings row, so it cannot run in a resolution door"),
        )
    })?;
    let mut args = Vec::new();
    for flag in row.flags {
        args.push(fill(flag, inputs, None)?);
    }
    for registry in inputs.cargo_registries {
        if !registry
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("cargo registry name {registry:?} is not a plain name"),
            ));
        }
        for flag in row.per_registry {
            args.push(fill(flag, inputs, Some(registry))?);
        }
    }
    let mut env: Vec<(OsString, OsString)> = row
        .env
        .iter()
        .chain(GIT_ENV)
        .map(|(key, value)| (OsString::from(key), OsString::from(value)))
        .collect();
    let mut config: Vec<(&str, &str)> = extra_git
        .iter()
        .map(|(key, value)| (key.as_str(), value.as_str()))
        .collect();
    config.extend(GIT_FORCED.iter().copied());
    env.push(("GIT_CONFIG_COUNT".into(), config.len().to_string().into()));
    for (index, (key, value)) in config.into_iter().enumerate() {
        env.push((format!("GIT_CONFIG_KEY_{index}").into(), key.into()));
        env.push((format!("GIT_CONFIG_VALUE_{index}").into(), value.into()));
    }
    let mut unset: Vec<&'static str> = row.unset.to_vec();
    unset.extend(GIT_UNSET);
    Ok(Forced { args, env, unset })
}

fn fill(flag: &str, inputs: &ForcedInputs<'_>, registry: Option<&str>) -> io::Result<OsString> {
    let mut text = flag.to_string();
    let paths = [
        ("@GIT@", inputs.git),
        ("@SH@", inputs.sh),
        ("@RUST@", inputs.rust),
        ("@PYTHON@", inputs.python),
    ];
    for (placeholder, value) in paths {
        if !text.contains(placeholder) {
            continue;
        }
        let value = value.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("the forced setting {flag} needs {placeholder}, which was not given"),
            )
        })?;
        let value = value.to_str().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{} is not UTF-8", value.display()),
            )
        })?;
        text = text.replace(placeholder, value);
    }
    if let Some(registry) = registry {
        text = text.replace("@REGISTRY@", registry);
    }
    Ok(text.into())
}

// ---------------------------------------------------------------------------
// The signing key

/// The system read roots every tier can read. A signing key there is
/// readable by any resolution tool.
pub const SYSTEM_READ_ROOTS: &[&str] = &[
    "/usr",
    "/etc",
    "/opt",
    "/private/etc",
    "/Library",
    "/System",
];

/// The signing-key paths a door must keep out of every mounted root: the
/// one `TOG_SIGNING_KEY` names and the default `tog keygen` suggests.
pub fn signing_key_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Some(path) = std::env::var_os("TOG_SIGNING_KEY").filter(|path| !path.is_empty()) {
        paths.push(PathBuf::from(path));
    }
    if let Some(home) = std::env::var_os("HOME").filter(|home| !home.is_empty()) {
        paths.push(PathBuf::from(home).join(".tog").join("signing.key"));
    }
    paths
}

/// Every spelling of `path` worth comparing: as given (made absolute), and
/// with its existing ancestors resolved.
fn spellings(path: &Path) -> Vec<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(path))
            .unwrap_or_else(|_| path.to_path_buf())
    };
    let mut out = vec![absolute.clone()];
    let mut tail = PathBuf::new();
    let mut probe = absolute.as_path();
    loop {
        if let Ok(real) = fs::canonicalize(probe) {
            let resolved = real.join(&tail);
            if !out.contains(&resolved) {
                out.push(resolved);
            }
            break;
        }
        let (Some(parent), Some(name)) = (probe.parent(), probe.file_name()) else {
            break;
        };
        tail = Path::new(name).join(&tail);
        probe = parent;
    }
    out
}

/// Refuse when any of `protected` lies under any of `roots`.
pub fn refuse_protected_under_roots(protected: &[PathBuf], roots: &[PathBuf]) -> io::Result<()> {
    for key in protected {
        for spelling in spellings(key) {
            for root in roots {
                if spelling.starts_with(root) {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        format!(
                            "the signing key {} is under {}, which the resolution sandbox \
                             mounts, so the tool could read it; move the key (tog keygen \
                             <path outside the project, the store and the system roots>) and \
                             point TOG_SIGNING_KEY at it",
                            key.display(),
                            root.display()
                        ),
                    ));
                }
            }
        }
    }
    Ok(())
}

/// `tog keygen`: refuse a key path under a system read root.
pub fn refuse_key_under_system_root(path: &Path) -> io::Result<()> {
    let roots: Vec<PathBuf> = SYSTEM_READ_ROOTS.iter().map(PathBuf::from).collect();
    for spelling in spellings(path) {
        if let Some(root) = roots.iter().find(|root| spelling.starts_with(root)) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "{} is under {}, which every sandbox can read; keep the signing key \
                     outside the system directories (for example ~/.tog/signing.key)",
                    path.display(),
                    root.display()
                ),
            ));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The socket scan

/// Whether `confined_run` scans the mounted roots for sockets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SocketScan {
    Full,
    /// Tests only: mount the roots unscanned, to show the seccomp filter
    /// alone keeps a socket unreachable.
    #[cfg(debug_assertions)]
    SkippedForTest,
}

const SOCKET_SCAN_RECORD: &str = "socket-scan";

fn socket_error(root: &Path, socket: &Path) -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!(
            "{} holds a Unix socket at {}; the resolution sandbox mounts {} and a resolution \
             tool must not reach any host socket, so it did not run",
            root.display(),
            socket.display(),
            root.display()
        ),
    )
}

/// Walk `root` without following symlinks and return the first socket. A
/// directory owned by another user that this user may not list is skipped:
/// the sandboxed tool runs as this user and cannot list it either. Any
/// other error refuses.
pub(crate) fn find_socket(root: &Path) -> io::Result<Option<PathBuf>> {
    let metadata = fs::symlink_metadata(root)?;
    let file_type = metadata.file_type();
    if file_type.is_socket() {
        return Ok(Some(root.to_path_buf()));
    }
    if !file_type.is_dir() {
        return Ok(None);
    }
    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(error)
            if error.kind() == io::ErrorKind::PermissionDenied
                // SAFETY: getuid cannot fail.
                && metadata.uid() != unsafe { libc::getuid() } =>
        {
            return Ok(None)
        }
        Err(error) => {
            return Err(io::Error::new(
                error.kind(),
                format!("cannot scan {} for sockets: {error}", root.display()),
            ))
        }
    };
    for entry in entries {
        let entry = entry?;
        match find_socket(&entry.path()) {
            Ok(Some(found)) => return Ok(Some(found)),
            Ok(None) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(None)
}

/// The system roots the sandbox binds, scanned once per process.
fn scan_system_roots() -> io::Result<()> {
    static SCANNED: OnceLock<Result<(), String>> = OnceLock::new();
    SCANNED
        .get_or_init(|| {
            for root in system_roots() {
                if let Some(socket) = find_socket(&root).map_err(|error| error.to_string())? {
                    return Err(socket_error(&root, &socket).to_string());
                }
            }
            Ok(())
        })
        .clone()
        .map_err(|message| io::Error::new(io::ErrorKind::PermissionDenied, message))
}

/// `/usr`, each real top-level system directory the sandbox binds, and
/// the `/etc` entries.
fn system_roots() -> Vec<PathBuf> {
    let mut roots = vec![PathBuf::from("/usr")];
    for name in sandbox::SYSTEM_ROOT_ENTRIES {
        let path = Path::new("/").join(name);
        if fs::symlink_metadata(&path).is_ok_and(|meta| meta.is_dir()) {
            roots.push(path);
        }
    }
    for entry in sandbox::HOST_ETC_ENTRIES {
        if fs::symlink_metadata(entry).is_ok() {
            roots.push(PathBuf::from(entry));
        }
    }
    roots
}

/// Scan one read root. A store object is immutable, so a clean scan is
/// recorded under its id and not repeated.
fn scan_read_root(store: &Store, activity: &StoreActivity, root: &Path) -> io::Result<()> {
    let object = root
        .strip_prefix(store.root.join("objects"))
        .ok()
        .and_then(|rest| rest.to_str())
        .filter(|id| store::is_object_id(id))
        .map(str::to_string);
    if let Some(id) = &object {
        if store.read_record(SOCKET_SCAN_RECORD, id)? == Some(serde_json::json!("clean")) {
            return Ok(());
        }
    }
    if let Some(socket) = find_socket(root)? {
        return Err(socket_error(root, &socket));
    }
    if let Some(id) = &object {
        store.write_record(
            activity,
            SOCKET_SCAN_RECORD,
            id,
            &serde_json::json!("clean"),
        )?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The run

/// Where the tool's standard output goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stdout {
    Inherit,
    Capture,
}

/// One confined run.
#[derive(Debug)]
pub struct ConfinedRun<'a> {
    /// The tool, for messages ("npm"), and why it needs isolation
    /// ("can run programs a project's .npmrc names").
    pub tool: &'a str,
    pub why: &'a str,
    /// Whether policy denies `unconfined-resolution`.
    pub unconfined_denied: bool,
    pub snapshot: &'a Snapshot,
    /// The proxy's Unix socket on the host.
    pub proxy_socket: &'a Path,
    /// The tog executable to bind as the relay (`running_executable()` in
    /// production).
    pub executable: &'a Path,
    /// The tool's argv; `argv[0]` an absolute path inside a bound root.
    pub argv: &'a [OsString],
    /// A real path inside a snapshot root or the scratch directory.
    pub cwd: &'a Path,
    /// The whole environment, built from empty by the caller with the
    /// forced settings applied. `HOME`, `TMPDIR` and `XDG_CACHE_HOME`
    /// default into the snapshot's scratch directory.
    pub env: &'a [(OsString, OsString)],
    /// Store objects (the tool, its runtime) bound read-only at their paths.
    pub read_roots: &'a [PathBuf],
    pub stdout: Stdout,
    pub socket_scan: SocketScan,
}

/// One program the tool tree executed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Exec {
    pub pid: i32,
    pub parent: i32,
    pub path: Option<String>,
}

/// What a confined run produced. By the time it is returned, every process
/// of the tool's tree is dead.
#[derive(Clone, Debug)]
pub struct ConfinedOutcome {
    pub tier: TierOffer,
    pub status: ToolStatus,
    pub execs: Vec<Exec>,
    /// Processes the relay had to kill after the tool exited.
    pub killed: usize,
    /// The tool's standard output, with `Stdout::Capture`.
    pub stdout: Vec<u8>,
}

/// The running tog executable, resolved before any sandbox starts.
pub fn running_executable() -> io::Result<PathBuf> {
    let path = fs::read_link("/proc/self/exe")?;
    if !fs::metadata(&path)?.is_file() {
        return Err(io::Error::other(format!(
            "the running tog executable {} is not a regular file",
            path.display()
        )));
    }
    Ok(path)
}

/// Run `run.argv` confined. The tool's exit status is returned, not
/// judged: a failing tool is `Ok` with a failing `status`. Setup failures,
/// refusals and a relay that broke are errors.
pub fn confined_run(
    store: &Store,
    activity: &StoreActivity,
    run: &ConfinedRun<'_>,
) -> io::Result<ConfinedOutcome> {
    store.require_activity(activity, "confined resolution")?;
    let (offers, missing) = probe_tiers(activity);
    let tier = choose_tier(&offers, &missing, run.unconfined_denied, run.tool, run.why)?;
    let bwrap = sandbox::bwrap_preflight_with_activity(Some(activity))?;
    let mounts = Mounts::check(store, activity, run)?;
    let args = proxy_args(run, &mounts)?;
    let (reader, writer) = pipe()?;
    let log = std::thread::spawn(move || read_log(reader));
    let mut command = sandbox::bwrap_command(bwrap)?;
    command.args(&args);
    pass_as_fd3(&mut command, writer.as_raw_fd());
    let result = start_confined(&mut command, activity, run.stdout);
    drop(command);
    drop(writer);
    let log = log
        .join()
        .map_err(|_| io::Error::other("the exec log reader panicked"))?;
    let (status, stderr, stdout) = result?;
    let records = relay::parse_log(&log?)?;
    outcome(tier, status, &stderr, stdout, records)
}

/// Start the bubblewrap command of a confined run: exit status, stderr
/// prefix, and captured stdout.
// Reviewed site (tests/architecture.rs): the door: a confined census tool starts here.
#[allow(clippy::disallowed_methods)]
fn start_confined(
    command: &mut std::process::Command,
    activity: &StoreActivity,
    stdout: Stdout,
) -> io::Result<(std::process::ExitStatus, Vec<u8>, Vec<u8>)> {
    match stdout {
        Stdout::Inherit => crate::kernel::supervise::status_with_stderr(command, activity)
            .map(|(status, stderr)| (status, stderr, Vec::new())),
        Stdout::Capture => crate::kernel::supervise::output(command, activity)
            .map(|output| (output.status, output.stderr, output.stdout)),
    }
}

fn outcome(
    tier: TierOffer,
    status: std::process::ExitStatus,
    stderr: &[u8],
    stdout: Vec<u8>,
    records: Vec<RelayRecord>,
) -> io::Result<ConfinedOutcome> {
    let mut execs = Vec::new();
    let mut tool = None;
    let mut killed = None;
    for record in records {
        match record {
            RelayRecord::Exec { pid, parent, path } => execs.push(Exec { pid, parent, path }),
            RelayRecord::Tool(status) => tool = Some(status),
            RelayRecord::Quiesced { killed: count } => killed = Some(count),
            RelayRecord::Error { message } => {
                return Err(io::Error::other(format!(
                    "the resolution relay failed: {message}"
                )))
            }
        }
    }
    match (tool, killed) {
        (Some(status), Some(killed)) => Ok(ConfinedOutcome {
            tier,
            status,
            execs,
            killed,
            stdout,
        }),
        _ if stderr.starts_with(b"bwrap:") => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            sandbox::explained_bwrap_stderr(&String::from_utf8_lossy(stderr)),
        )),
        _ => Err(io::Error::other(format!(
            "the resolution relay ended ({status}) without reporting the tool's status and \
             a stopped process tree; nothing it produced is used"
        ))),
    }
}

/// The checked, canonical mounts of one run.
struct Mounts {
    read_roots: Vec<PathBuf>,
    proxy_socket: PathBuf,
    executable: PathBuf,
    scratch: PathBuf,
    cwd: PathBuf,
}

impl Mounts {
    fn check(store: &Store, activity: &StoreActivity, run: &ConfinedRun<'_>) -> io::Result<Mounts> {
        let snapshot_roots: Vec<PathBuf> = run
            .snapshot
            .roots()
            .iter()
            .map(|root| root.real.clone())
            .collect();
        let mut read_roots = Vec::new();
        for root in run.read_roots {
            let real = fs::canonicalize(root)?;
            if snapshot_roots
                .iter()
                .any(|snap| real.starts_with(snap) || snap.starts_with(&real))
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "the read root {} overlaps the project snapshot; the real project is \
                         never mounted",
                        real.display()
                    ),
                ));
            }
            read_roots.push(real);
        }
        let proxy_socket = fs::canonicalize(run.proxy_socket)?;
        if !fs::symlink_metadata(&proxy_socket)?.file_type().is_socket() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{} is not the proxy's socket", proxy_socket.display()),
            ));
        }
        let executable = fs::canonicalize(run.executable)?;
        let scratch = fs::canonicalize(run.snapshot.scratch())?;
        let cwd = fs::canonicalize(run.cwd)?;
        if !snapshot_roots
            .iter()
            .chain(std::iter::once(&scratch))
            .any(|root| cwd.starts_with(root))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "the working directory {} is outside the snapshot",
                    cwd.display()
                ),
            ));
        }
        let program = run
            .argv
            .first()
            .map(Path::new)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no tool to run"))?;
        if !program.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("the tool {} is not an absolute path", program.display()),
            ));
        }
        // Every tree the tool can read, for the signing-key rule.
        let mut bound: Vec<PathBuf> = system_roots();
        bound.extend(read_roots.iter().cloned());
        bound.extend(snapshot_roots.iter().cloned());
        bound.push(run.snapshot.stage().to_path_buf());
        bound.push(executable.clone());
        refuse_protected_under_roots(&signing_key_paths(), &bound)?;
        let scan = run.socket_scan == SocketScan::Full;
        if scan {
            scan_system_roots()?;
            for root in &read_roots {
                scan_read_root(store, activity, root)?;
            }
        }
        Ok(Mounts {
            read_roots,
            proxy_socket,
            executable,
            scratch,
            cwd,
        })
    }
}

/// The bubblewrap argv of a `Proxy` run.
fn proxy_args(run: &ConfinedRun<'_>, mounts: &Mounts) -> io::Result<Vec<OsString>> {
    let mut args: Vec<OsString> = [
        "--unshare-user",
        "--unshare-net",
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-uts",
        "--hostname",
        "tog",
        "--unshare-cgroup-try",
        "--die-with-parent",
        "--new-session",
        "--clearenv",
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    args.extend(sandbox::system_root_args(Path::new("/"))?);
    for entry in sandbox::HOST_ETC_ENTRIES {
        if Path::new(entry).exists() {
            sandbox::push_bind(&mut args, "--ro-bind", entry, entry);
        }
    }
    for (flag, path) in [("--dev", "/dev"), ("--proc", "/proc"), ("--tmpfs", "/tmp")] {
        args.push(flag.into());
        args.push(path.into());
    }
    for root in &mounts.read_roots {
        sandbox::push_bind_path(&mut args, "--ro-bind", root);
    }
    for root in run.snapshot.roots() {
        args.push("--bind".into());
        args.push(root.staged.clone().into_os_string());
        args.push(root.real.clone().into_os_string());
    }
    sandbox::push_bind_path(&mut args, "--bind", &mounts.scratch);
    args.push("--ro-bind".into());
    args.push(mounts.proxy_socket.clone().into_os_string());
    args.push(relay::PROXY_SOCKET.into());
    args.push("--ro-bind".into());
    args.push(mounts.executable.clone().into_os_string());
    args.push(relay::TOG_EXECUTABLE.into());
    for (key, value) in door_env(run, &mounts.scratch)? {
        args.push("--setenv".into());
        args.push(key);
        args.push(value);
    }
    args.push("--chdir".into());
    args.push(mounts.cwd.clone().into_os_string());
    for part in [
        relay::TOG_EXECUTABLE,
        relay::VERB,
        "--exec-log-fd",
        "3",
        relay::PROXY_SOCKET,
        relay::LISTEN_ADDRESS,
        "--",
    ] {
        args.push(part.into());
    }
    args.extend(run.argv.iter().cloned());
    Ok(args)
}

/// The caller's environment plus scratch defaults. Keys must be plain.
fn door_env(run: &ConfinedRun<'_>, scratch: &Path) -> io::Result<Vec<(OsString, OsString)>> {
    let mut env: Vec<(OsString, OsString)> = Vec::new();
    for (key, value) in run.env {
        let bytes = key.as_bytes();
        if bytes.is_empty()
            || bytes.contains(&b'=')
            || bytes.contains(&0)
            || value.as_bytes().contains(&0)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{key:?} is not an environment variable name"),
            ));
        }
        env.retain(|(existing, _)| existing != key);
        env.push((key.clone(), value.clone()));
    }
    for (key, sub) in [
        ("HOME", "home"),
        ("TMPDIR", "tmp"),
        ("XDG_CACHE_HOME", "cache"),
    ] {
        if env.iter().any(|(existing, _)| existing == key) {
            continue;
        }
        let path = scratch.join(sub);
        fs::create_dir_all(&path)?;
        env.push((key.into(), path.into_os_string()));
    }
    Ok(env)
}

/// The exec log's pipe, both ends close-on-exec from the moment they
/// exist, so no child started meanwhile by another thread inherits one.
fn pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    let (reader, writer) = std::io::pipe()?;
    Ok((OwnedFd::from(reader), OwnedFd::from(writer)))
}

/// Hand `fd` to bubblewrap as descriptor 3 (the relay's exec log). This
/// runs after `bwrap_command` marked every inherited descriptor
/// close-on-exec, so 3 is the only one that survives.
fn pass_as_fd3(command: &mut std::process::Command, fd: RawFd) {
    use std::os::unix::process::CommandExt;
    // SAFETY: the closure calls only dup2/fcntl, which are
    // async-signal-safe and allocate nothing.
    unsafe {
        command.pre_exec(move || {
            if fd == relay::EXEC_LOG_FD {
                if libc::fcntl(fd, libc::F_SETFD, 0) != 0 {
                    return Err(io::Error::last_os_error());
                }
            } else if libc::dup2(fd, relay::EXEC_LOG_FD) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

/// The exec log is small; a relay that writes more than this is broken.
const LOG_CAP: u64 = 64 * 1024 * 1024;

fn read_log(reader: OwnedFd) -> io::Result<Vec<u8>> {
    let file = fs::File::from(reader);
    let mut bytes = Vec::new();
    file.take(LOG_CAP + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > LOG_CAP {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the resolution relay's exec log is too large",
        ));
    }
    Ok(bytes)
}

/// Whether a snapshot of `lock_root` would copy the signing key, for a
/// caller that wants to refuse before building one.
pub fn refuse_key_in_snapshot_roots(roots: &[PathBuf]) -> io::Result<()> {
    refuse_protected_under_roots(&signing_key_paths(), roots)
}

/// The messages a refused door names its paths in, for callers that
/// collect several.
pub fn listing(items: &[String]) -> String {
    snapshot::listing(items)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::testutil::TempDir;
    use serde_json::Value;

    fn offer(fenced: bool) -> TierOffer {
        TierOffer {
            engine: Engine::Bubblewrap,
            fenced,
        }
    }

    fn missing() -> Vec<Missing> {
        vec![Missing {
            capability: "bubblewrap",
            reason: "setting up uid map: Permission denied".to_string(),
            fix: "install bubblewrap and allow it unprivileged user namespaces".to_string(),
        }]
    }

    #[test]
    fn a_fenced_engine_is_chosen_first() {
        let chosen = choose_tier(&[offer(false), offer(true)], &[], true, "npm", "x").unwrap();
        assert!(chosen.fenced);
        assert_eq!(chosen.isolation(), "confined");
        assert!(chosen.exceptions().is_empty());
    }

    #[test]
    fn an_unfenced_engine_records_unconfined_resolution_unless_denied() {
        let chosen = choose_tier(&[offer(false)], &[], false, "npm", "x").unwrap();
        assert_eq!(chosen.isolation(), "isolated");
        assert_eq!(chosen.exceptions(), &["unconfined-resolution"]);
        let refused = choose_tier(&[offer(false)], &missing(), true, "npm", "x")
            .unwrap_err()
            .to_string();
        assert!(refused.contains("unconfined-resolution"), "{refused}");
    }

    #[test]
    fn no_engine_names_the_tool_why_and_every_missing_capability() {
        let error =
            choose_tier(&[], &missing(), false, "Bundler", "evaluates the Gemfile").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        let message = error.to_string();
        for needle in [
            "Bundler evaluates the Gemfile",
            "bubblewrap: setting up uid map: Permission denied",
            "fix: install bubblewrap",
            "no other isolation backend",
        ] {
            assert!(message.contains(needle), "{needle}: {message}");
        }
    }

    fn fixture(tool_dir: &str) -> Value {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/proxy/forced")
            .join(tool_dir)
            .join("settings.json");
        serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
    }

    fn census_inputs() -> (PathBuf, PathBuf, PathBuf, PathBuf) {
        (
            PathBuf::from("/usr/bin/git"),
            PathBuf::from("/bin/sh"),
            PathBuf::from("@RUST@"),
            PathBuf::from("@PYTHON@"),
        )
    }

    fn render(tool: &str) -> Forced {
        let (git, sh, rust, python) = census_inputs();
        let registries = vec!["evil".to_string()];
        forced_settings(
            tool,
            &ForcedInputs {
                git: Some(&git),
                sh: Some(&sh),
                rust: Some(&rust),
                python: Some(&python),
                cargo_registries: &registries,
            },
            &[],
        )
        .unwrap()
    }

    fn env_value<'a>(forced: &'a Forced, key: &str) -> Option<&'a OsStr> {
        forced
            .env
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.as_os_str())
    }

    fn git_config(forced: &Forced) -> Vec<(String, String)> {
        let count: usize = env_value(forced, "GIT_CONFIG_COUNT")
            .unwrap()
            .to_str()
            .unwrap()
            .parse()
            .unwrap();
        (0..count)
            .map(|index| {
                (
                    env_value(forced, &format!("GIT_CONFIG_KEY_{index}"))
                        .unwrap()
                        .to_string_lossy()
                        .into_owned(),
                    env_value(forced, &format!("GIT_CONFIG_VALUE_{index}"))
                        .unwrap()
                        .to_string_lossy()
                        .into_owned(),
                )
            })
            .collect()
    }

    /// The last value git would read for `key` (config keys are
    /// case-insensitive in their section and name).
    fn git_effective(forced: &Forced, key: &str) -> Option<String> {
        git_config(forced)
            .into_iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case(key))
            .map(|(_, value)| value)
            .next_back()
    }

    /// Every flag the census proved (`forced_flags` in each fixture) is in
    /// the rendered row, a flag and its separate value adjacent.
    fn assert_flags(tool: &str, forced: &Forced, fixture: &Value) {
        let Some(flags) = fixture["forced_flags"].as_array() else {
            return;
        };
        let flags: Vec<&str> = flags.iter().map(|flag| flag.as_str().unwrap()).collect();
        let rendered: Vec<String> = forced
            .args
            .iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        let mut index = 0;
        while index < flags.len() {
            let flag = flags[index];
            let value = flags
                .get(index + 1)
                .filter(|next| flag.starts_with("--") && !next.starts_with('-'));
            match value {
                Some(value) => {
                    assert!(
                        rendered
                            .windows(2)
                            .any(|pair| pair[0] == flag && pair[1] == *value),
                        "{tool}: {flag} {value} is not forced: {rendered:?}"
                    );
                    index += 2;
                }
                None => {
                    assert!(
                        rendered.iter().any(|arg| arg == flag),
                        "{tool}: {flag} is not forced: {rendered:?}"
                    );
                    index += 1;
                }
            }
        }
    }

    #[test]
    fn forced_program_settings_hold_for_every_census_tool() {
        let census = fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/proxy/census/forced.jsonl"),
        )
        .unwrap();
        for line in census.lines().filter(|line| !line.trim().is_empty()) {
            let row: Value = serde_json::from_str(line).unwrap();
            let tool = row["tool"].as_str().unwrap();
            assert!(
                forced_tools().any(|known| known == tool),
                "census tool {tool} has no forced-settings row"
            );
            // Only project code a tool runs by design may run in the
            // forced run; isolation is its control.
            for hit in row["forced_hits"].as_array().into_iter().flatten() {
                assert!(
                    hit.as_str().unwrap().starts_with("by-design:"),
                    "{tool}: a program-naming setting still ran: {hit}"
                );
            }
        }
        for (dir, tool) in [
            ("npm", "npm"),
            ("pnpm", "pnpm"),
            ("cargo", "cargo"),
            ("uv", "uv"),
            ("vcs", "git"),
            ("go", "go"),
            ("bundler", "bundler"),
            ("mix", "mix"),
            ("dotnet", "dotnet"),
        ] {
            let fixture = fixture(dir);
            assert_eq!(fixture["tool"].as_str(), Some(tool));
            let forced = render(tool);
            assert_flags(tool, &forced, &fixture);
            // git's settings reach every tool, since each may start git.
            for (key, value) in GIT_FORCED {
                assert_eq!(
                    git_effective(&forced, key).as_deref(),
                    Some(*value),
                    "{tool} {key}"
                );
            }
            assert_eq!(
                env_value(&forced, "GIT_CONFIG_NOSYSTEM"),
                Some(OsStr::new("1"))
            );
            for unset in ["GIT_SSH_COMMAND", "GIT_ASKPASS", "SSH_ASKPASS"] {
                assert!(forced.unset.contains(&unset), "{tool}: {unset}");
            }
        }
        // git: every setting the fixture's repository names is overridden
        // by a forced value that runs nothing.
        let git = render("git");
        for setting in fixture("vcs")["settings"].as_array().unwrap() {
            let key = setting["key"].as_str().unwrap();
            let effective =
                git_effective(&git, key).unwrap_or_else(|| panic!("git: {key} is not forced"));
            assert!(
                matches!(effective.as_str(), "" | "false" | "never" | "/dev/null"),
                "git: {key}={effective} could run something"
            );
        }
        // go: every variable a control run set is forced or removed. The
        // proxy variables are the caller's (the mirror, with no `direct`).
        let go = render("go");
        for setting in fixture("go")["settings"].as_array().unwrap() {
            for key in setting["env"].as_object().unwrap().keys() {
                if matches!(key.as_str(), "GOPROXY" | "GOSUMDB") {
                    continue;
                }
                assert!(
                    env_value(&go, key).is_some() || go.unset.contains(&key.as_str()),
                    "go: {key} is neither forced nor unset"
                );
            }
        }
        assert_eq!(env_value(&go, "GOTOOLCHAIN"), Some(OsStr::new("local")));
        assert_eq!(env_value(&go, "GOVCS"), Some(OsStr::new("*:off")));
        let bundler = render("bundler");
        assert_eq!(
            env_value(&bundler, "BUNDLE_IGNORE_CONFIG"),
            Some(OsStr::new("1"))
        );
        let dotnet = render("dotnet");
        assert_eq!(
            env_value(&dotnet, "DOTNET_EnableDiagnostics"),
            Some(OsStr::new("0"))
        );
        assert!(dotnet
            .args
            .contains(&OsString::from("--disable-build-servers")));
    }

    #[test]
    fn a_caller_git_setting_cannot_override_a_forced_one() {
        let (git, sh, ..) = census_inputs();
        let forced = forced_settings(
            "npm",
            &ForcedInputs {
                git: Some(&git),
                sh: Some(&sh),
                ..ForcedInputs::default()
            },
            &[
                (
                    "http.proxy".to_string(),
                    "http://127.0.0.1:8119".to_string(),
                ),
                ("core.fsmonitor".to_string(), "/evil".to_string()),
            ],
        )
        .unwrap();
        assert_eq!(
            git_effective(&forced, "core.fsmonitor").as_deref(),
            Some("false")
        );
        assert_eq!(
            git_effective(&forced, "http.proxy").as_deref(),
            Some("http://127.0.0.1:8119")
        );
        let mut env = vec![
            (
                OsString::from("NODE_OPTIONS"),
                OsString::from("--require=/evil"),
            ),
            (OsString::from("GIT_CONFIG_NOSYSTEM"), OsString::from("0")),
            (OsString::from("PATH"), OsString::from("/store/bin")),
        ];
        forced.apply(&mut env);
        assert!(!env.iter().any(|(key, _)| key == "NODE_OPTIONS"));
        assert_eq!(
            env.iter()
                .filter(|(key, _)| key == "GIT_CONFIG_NOSYSTEM")
                .map(|(_, value)| value.clone())
                .collect::<Vec<_>>(),
            vec![OsString::from("1")]
        );
    }

    #[test]
    fn a_missing_store_path_or_unknown_tool_is_refused() {
        assert!(forced_settings("npm", &ForcedInputs::default(), &[]).is_err());
        assert!(forced_settings("yarn", &ForcedInputs::default(), &[]).is_err());
        let rust = PathBuf::from("/store/rust");
        let bad = vec!["a\"b".to_string()];
        assert!(forced_settings(
            "cargo",
            &ForcedInputs {
                rust: Some(&rust),
                cargo_registries: &bad,
                ..ForcedInputs::default()
            },
            &[]
        )
        .is_err());
    }

    #[test]
    fn door_profile_denies_reading_the_signing_key() {
        let temp = TempDir::named("confine-key");
        let project = temp.0.join("project");
        fs::create_dir_all(&project).unwrap();
        let project = project.canonicalize().unwrap();
        let inside = project.join("signing.key");
        let outside = temp.0.join("elsewhere/signing.key");
        let roots = vec![project.clone(), PathBuf::from("/usr")];
        let error =
            refuse_protected_under_roots(std::slice::from_ref(&inside), &roots).unwrap_err();
        assert!(error.to_string().contains("signing key"), "{error}");
        assert!(refuse_protected_under_roots(&[outside], &roots).is_ok());
        // A symlinked spelling of the same place is caught too.
        let alias = temp.0.join("alias");
        std::os::unix::fs::symlink(&project, &alias).unwrap();
        assert!(refuse_protected_under_roots(&[alias.join("signing.key")], &roots).is_err());
    }

    #[test]
    fn keygen_refuses_a_path_under_a_system_read_root() {
        for path in [
            "/usr/local/share/tog.key",
            "/etc/tog/signing.key",
            "/opt/tog/key",
            "/private/etc/key",
            "/Library/tog/key",
            "/System/key",
        ] {
            let error = refuse_key_under_system_root(Path::new(path)).unwrap_err();
            assert!(
                error.to_string().contains("system directories"),
                "{path}: {error}"
            );
        }
        let temp = TempDir::named("keygen-root");
        assert!(refuse_key_under_system_root(&temp.0.join("signing.key")).is_ok());
        assert!(refuse_key_under_system_root(Path::new("/usrlocal/key")).is_ok());
    }

    /// A socket anywhere in a store read root refuses the door, and a
    /// clean object's scan is recorded and trusted after.
    #[test]
    fn door_refuses_a_socket_in_a_store_read_root() {
        let temp = TempDir::named("confine-scan");
        let root = temp.0.join("store");
        for sub in ["objects", "meta", "tmp", "records"] {
            fs::create_dir_all(root.join(sub)).unwrap();
        }
        let store = Store {
            root: root.canonicalize().unwrap(),
        };
        let activity = store
            .activity(crate::kernel::activity::ActivityMode::Shared)
            .unwrap();
        let clean_id = format!("{}-node-22", "a".repeat(40));
        let dirty_id = format!("{}-node-22", "b".repeat(40));
        let clean = store.root.join("objects").join(&clean_id);
        let dirty = store.root.join("objects").join(&dirty_id);
        for object in [&clean, &dirty] {
            fs::create_dir_all(object.join("lib/deep")).unwrap();
            fs::write(object.join("lib/file"), b"x").unwrap();
        }
        let short = PathBuf::from(format!("/tmp/tog-scan-{}", std::process::id()));
        let _ = fs::remove_file(&short);
        let _listener = std::os::unix::net::UnixListener::bind(&short).unwrap();
        fs::rename(&short, dirty.join("lib/deep/agent.sock")).unwrap();

        let error = scan_read_root(&store, &activity, &dirty).unwrap_err();
        assert!(error.to_string().contains("agent.sock"), "{error}");
        assert_eq!(
            store.read_record(SOCKET_SCAN_RECORD, &dirty_id).unwrap(),
            None
        );
        scan_read_root(&store, &activity, &clean).unwrap();
        assert_eq!(
            store.read_record(SOCKET_SCAN_RECORD, &clean_id).unwrap(),
            Some(serde_json::json!("clean"))
        );
    }

    /// The system-root scan runs to the end on this host: every directory
    /// it cannot list belongs to another user. A host with a socket under
    /// `/usr` is reported, not failed: every door there refuses, by design.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_system_root_scan_completes_on_this_host() {
        match scan_system_roots() {
            Ok(()) => {}
            Err(error) if error.to_string().contains("holds a Unix socket") => {
                eprintln!("note: {error}");
            }
            Err(error) => panic!("{error}"),
        }
    }

    #[test]
    fn a_relay_log_without_a_status_is_an_error() {
        use std::os::unix::process::ExitStatusExt;
        let status = std::process::ExitStatus::from_raw(0);
        let tier = offer(true);
        let error = outcome(tier, status, b"", Vec::new(), Vec::new()).unwrap_err();
        assert!(error.to_string().contains("without reporting"), "{error}");
        let error =
            outcome(tier, status, b"bwrap: Can't mount", Vec::new(), Vec::new()).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        let done = outcome(
            tier,
            status,
            b"",
            Vec::new(),
            vec![
                RelayRecord::Exec {
                    pid: 2,
                    parent: 1,
                    path: Some("/usr/bin/true".to_string()),
                },
                RelayRecord::Tool(ToolStatus::Code(3)),
                RelayRecord::Quiesced { killed: 1 },
            ],
        )
        .unwrap();
        assert_eq!(done.status, ToolStatus::Code(3));
        assert_eq!(done.killed, 1);
        assert_eq!(done.execs.len(), 1);
    }
}

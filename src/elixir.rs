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

use crate::fetch::{download_verified, download_verified_digest, Digest};
use crate::sandbox::{force_env, run_build_spec, BuildSpec};
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
// Community-maintained builds from erlef/otp_builds (relocatable by
// construction: their Install step runs pre-packaging).
const OTP_URL: &str = "https://github.com/erlef/otp_builds/releases/download/OTP-29.0.5/otp-aarch64-apple-darwin.tar.gz";
const OTP_SHA256: &str = "24b9e00da2b9ad25b1f182e2efd73ff316e46ec4b143c0cc3c69dbd27d5a594d";

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
pub fn beam_fingerprint() -> String {
    let joined = format!("{OTP_SHA256}:{ELIXIR_SHA256}:{HEX_SHA512}:{REBAR3_SHA512}");
    hex::encode(&Sha256::digest(joined.as_bytes())[..8])
}

/// Ensure the composite BEAM toolchain object: otp/ + elixir/ (separate
/// roots, per Sol — never merge their trees) + archives/ (unpacked Hex) +
/// rebar3 escript.
pub fn ensure_beam(store: &Store) -> io::Result<PathBuf> {
    let identity = Identity {
        kind: "beam".into(),
        name: "beam".into(),
        version: format!("{OTP_VERSION}-elixir{ELIXIR_VERSION}"),
        inputs: BTreeMap::from([
            ("schema".to_string(), "beam-toolchain/1".to_string()),
            ("otp_sha256".to_string(), OTP_SHA256.to_string()),
            ("elixir_sha256".to_string(), ELIXIR_SHA256.to_string()),
            ("hex_sha512".to_string(), HEX_SHA512.to_string()),
            ("rebar3_sha512".to_string(), REBAR3_SHA512.to_string()),
            (
                "versions".to_string(),
                format!("hex{HEX_VERSION}:rebar{REBAR3_VERSION}"),
            ),
            ("platform".to_string(), "aarch64-apple-darwin".to_string()),
        ]),
    };
    let id = identity.object_id();
    if store.has(&id) {
        crate::policy::check_cached(store, &id)?;
        return Ok(store.object_path(&id));
    }
    let otp_tar = download_verified(store, OTP_URL, OTP_SHA256)?;
    let elixir_zip = download_verified(store, ELIXIR_URL, ELIXIR_SHA256)?;
    let hex_ez = download_verified_digest(store, HEX_URL, &Digest::sha512(HEX_SHA512)?)?;
    let rebar3 = download_verified_digest(store, REBAR3_URL, &Digest::sha512(REBAR3_SHA512)?)?;

    let staged = store.stage()?;
    fs::create_dir_all(staged.join("otp"))?;
    let st = Command::new("/usr/bin/tar")
        .args(["-xzf"])
        .arg(&otp_tar)
        .args(["-C"])
        .arg(staged.join("otp"))
        .status()?;
    if !st.success() || !staged.join("otp/bin/erl").is_file() {
        return Err(err("OTP extraction failed or has unexpected layout"));
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
pub fn realize_deps(store: &Store, plan: &ElixirPlan, beam_obj: &Path) -> io::Result<PathBuf> {
    validate_plan(plan)?;
    let mut inputs = BTreeMap::from([
        ("schema".to_string(), "hex-deps/1".to_string()),
        // .hex markers are generated under the pinned toolchain; their
        // bytes live in the object.
        ("beam".to_string(), beam_fingerprint()),
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
        let tar = download_verified(store, &url, &d.outer_sha256)
            .map_err(|e| err(format!("{}: {e}", d.app)))?;
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
                .map_err(|e| err(format!("{}: missing {part} in tarball: {e}", d.app)))?;
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
        crate::project::clone_tree(&deps_obj, &tmp)?;
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
            "beam_fingerprint": beam_fingerprint(),
            "plan": plan,
        }),
    )?;
    Ok(proj_dir)
}

/// Build root, qualified by the toolchain fingerprint (stale BEAM/native
/// artifacts across OTP/Elixir upgrades are a real hazard — Sol).
pub fn build_root(project_dir: &Path) -> PathBuf {
    project_dir.join(format!("_build/blanket-{}", beam_fingerprint()))
}

/// Sandboxed `mix compile`: network denied, writes only the qualified
/// build root, the deps projection (native builds write in-tree), scratch.
pub fn build_sandboxed(
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
    let build = build_root(&project_dir);
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
    let result = run_build_spec(&spec).map_err(|e| {
        err(format!(
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
        let root = build_root(Path::new("/p"));
        assert!(root.display().to_string().contains("_build/blanket-"));
        assert_eq!(beam_fingerprint().len(), 16);
    }
}

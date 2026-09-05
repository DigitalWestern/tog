//! The Ruby tailor: Bundler-delegated planning, blanket-verified gems,
//! immutable GEM_HOME objects, sandboxed native-extension installs.
//!
//! Sol review 5 shaped this: platform selection and lock parsing are
//! DELEGATED to the pinned Ruby's own Bundler/RubyGems (a helper script —
//! Gem::Platform matching has wildcards and specificity scores no hand
//! parser should reimplement), while every artifact byte is still pinned
//! and verified by blanket. Bundler's local .bundle/config outranks plain
//! env vars, so every blanket-controlled invocation scrubs BUNDLE_*/RUBY*
//! preload vars and sets BUNDLE_IGNORE_CONFIG=1.

use crate::fetch::download_verified;
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

const RUBY_VERSION: &str = "3.4.6";
// Homebrew portable-ruby: relocatable, bundler included; the ruby Homebrew
// itself ships on. Newest PORTABLE artifact (ruby-lang 3.4.x source may be
// newer; documented gap until a newer portable build exists).
//
// Both 3.4.6 bottles were inspected (2026-09-05): root `portable-ruby/3.4.6/`,
// no symlinks, `#!/bin/sh` wrappers that `exec "$bindir/ruby"` relative to
// $0, `--enable-load-relative` (RbConfig prefix follows the object path) and
// `--with-static-linked-ext` (openssl/zlib/yaml/ffi compiled into
// `bin/ruby`). The Linux binary's NEEDED set is glibc only; its RUNPATH still
// lists `/home/linuxbrew/...` build directories but nothing NEEDED lives
// there, so it is inert provenance (like `configure_args`) and is NOT
// rewritten: no staging repair, hence no relocation-recipe identity input.
// RubyGems reports `Gem::Platform.local` = `x86_64-linux` for that bottle,
// which is neither the bottle tag (`x86_64_linux`) nor the Rust triple; the
// plan records whatever the pinned interpreter says.
struct RubyPin {
    platform: Platform,
    url: &'static str,
    sha256: &'static str,
}

const RUBY_PINS: &[RubyPin] = &[RubyPin {
    platform: Platform::Aarch64AppleDarwin,
    url: "https://github.com/Homebrew/homebrew-portable-ruby/releases/download/3.4.6/portable-ruby-3.4.6.arm64_big_sur.bottle.tar.gz",
    sha256: "62fe925f284cc38aac68b9a42b02cd90de753f8832e8866be3fd60558dd70f67",
}, RubyPin {
    platform: Platform::X86_64UnknownLinuxGnu,
    url: "https://github.com/Homebrew/homebrew-portable-ruby/releases/download/3.4.6/portable-ruby-3.4.6.x86_64_linux.bottle.tar.gz",
    sha256: "40932a3950ccc8bf9d13d98e692e5518427cc66b4f9520956cec349629d25259",
}];

fn ruby_pin(platform: Platform) -> io::Result<&'static RubyPin> {
    RUBY_PINS
        .iter()
        .find(|pin| pin.platform == platform)
        .ok_or_else(|| no_pin("ruby", platform, "stage 4"))
}

pub fn preflight_platform(platform: Platform) -> io::Result<()> {
    crate::platform::require_host(platform, "Ruby", "stage 4")?;
    ruby_pin(platform).map(|_| ())
}

fn ruby_identity(pin: &RubyPin) -> Identity {
    Identity {
        kind: "ruby".into(),
        name: "ruby".into(),
        version: RUBY_VERSION.into(),
        inputs: BTreeMap::from([
            ("schema".to_string(), "ruby-toolchain/1".to_string()),
            ("artifact_sha256".to_string(), pin.sha256.to_string()),
            ("platform".to_string(), pin.platform.triple().to_string()),
        ]),
    }
}

fn ruby_gems_identity(pin: &RubyPin, plan: &RubyPlan) -> Identity {
    let mut inputs = BTreeMap::from([
        ("schema".to_string(), "ruby-gems/1".to_string()),
        // Installer recipe AND wrapper-byte provenance: generated binstubs
        // embed interpreter paths.
        (
            "installer".to_string(),
            format!("ruby{}:{}", RUBY_VERSION, pin.sha256),
        ),
        ("ruby_platform".to_string(), plan.ruby_platform.clone()),
    ]);
    for g in &plan.gems {
        inputs.insert(format!("gem:{}", g.full_name), g.sha256.clone());
    }
    Identity {
        kind: "ruby-gems".into(),
        name: "gems".into(),
        version: plan.gems.len().to_string(),
        inputs,
    }
}

fn err(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

fn required_entry(root: &Path, relative: &str) -> io::Result<()> {
    let path = root.join(relative);
    let metadata = fs::symlink_metadata(&path).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("portable-ruby is missing {relative}: {e}"),
        )
    })?;
    if !metadata.is_file() && !metadata.file_type().is_symlink() {
        return Err(err(format!(
            "portable-ruby path is not a file: {}",
            path.display()
        )));
    }
    if metadata.file_type().is_symlink() {
        let root = root.canonicalize()?;
        let resolved = path.canonicalize().map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("portable-ruby has dangling symlink {}: {e}", path.display()),
            )
        })?;
        if !resolved.starts_with(&root) {
            return Err(err(format!(
                "portable-ruby symlink escapes the object: {} -> {}",
                path.display(),
                resolved.display()
            )));
        }
        if !resolved.is_file() {
            return Err(err(format!(
                "portable-ruby symlink does not resolve to a file: {}",
                path.display()
            )));
        }
    }
    Ok(())
}

fn find_file(root: &Path, wanted: &dyn Fn(&Path) -> bool) -> io::Result<Option<PathBuf>> {
    let metadata = fs::symlink_metadata(root)?;
    if metadata.file_type().is_symlink() {
        return Ok(None);
    }
    if metadata.is_file() {
        return Ok(wanted(root).then(|| root.to_path_buf()));
    }
    if !metadata.is_dir() {
        return Ok(None);
    }
    for entry in fs::read_dir(root)? {
        let path = entry?.path();
        if let Some(found) = find_file(&path, wanted)? {
            return Ok(Some(found));
        }
    }
    Ok(None)
}

fn validate_ruby_layout(root: &Path) -> io::Result<()> {
    required_entry(root, "bin/ruby")?;
    required_entry(root, "bin/gem")?;

    let bin = root.join("bin");
    let bundle = find_file(&bin, &|path| {
        path.file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name == "bundle" || name == "bundler" || name.starts_with("bundle"))
    })?;
    if bundle.is_none() {
        return Err(err(format!(
            "portable-ruby is missing a Bundler launcher under {}",
            bin.display()
        )));
    }

    let library = find_file(&root.join("lib"), &|path| {
        path.file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("libruby"))
    })?;
    if library.is_none() {
        return Err(err("portable-ruby is missing its Ruby runtime library"));
    }

    let header = find_file(&root.join("include"), &|path| {
        path.file_name().and_then(|name| name.to_str()) == Some("ruby.h")
    })?;
    if header.is_none() {
        return Err(err("portable-ruby is missing interpreter headers"));
    }
    Ok(())
}

fn extract_ruby_bottle(tarball: &Path, staged: &Path) -> io::Result<()> {
    // The verified Linux and Darwin bottles both use
    // portable-ruby/<version>/<tree>; this is deliberately not Node's
    // strip count. The archive remains unchanged in the verified cache.
    let status = Command::new("/usr/bin/tar")
        .args(["-xzf"])
        .arg(tarball)
        .args(["-C"])
        .arg(staged)
        .args(["--strip-components", "2"])
        .status()?;
    if !status.success() {
        return Err(err("portable-ruby extraction failed"));
    }
    validate_ruby_layout(staged)
}

/// Ensure the pinned portable Ruby is realized (interpreter at <obj>/bin/ruby).
pub fn ensure_ruby(store: &Store) -> io::Result<PathBuf> {
    ensure_ruby_for(store, Platform::host()?)
}

pub fn ensure_ruby_for(store: &Store, platform: Platform) -> io::Result<PathBuf> {
    crate::platform::require_host(platform, "Ruby", "stage 4")?;
    let pin = ruby_pin(platform)?;
    let identity = ruby_identity(pin);
    let id = identity.object_id();
    if store.has(&id) {
        crate::policy::check_cached(store, &id)?;
        return Ok(store.object_path(&id));
    }
    let tarball = download_verified(store, pin.url, pin.sha256)?;
    let staged = store.stage()?;
    if let Err(error) = extract_ruby_bottle(&tarball, &staged) {
        let _ = crate::store::remove_tree(&staged);
        return Err(error);
    }
    store.commit(&identity, &staged, &[]).map(|(path, _)| path)
}

/// The forced environment for EVERY blanket-controlled ruby/bundler run.
/// Removal lists close the .bundle/config and preload side doors.
const ENV_REMOVE_PREFIXES: &[&str] = &["BUNDLE_", "BUNDLER_"];
const ENV_REMOVE: &[&str] = &[
    "RUBYOPT",
    "RUBYLIB",
    "RUBYGEMS_GEMDEPS",
    "GEM_SPEC_CACHE",
    "GEM_HOME",
    "GEM_PATH",
];

fn forced_env(project_dir: &Path, gem_home: &Path) -> Vec<(String, String)> {
    vec![
        ("GEM_HOME".to_string(), gem_home.display().to_string()),
        ("GEM_PATH".to_string(), gem_home.display().to_string()),
        ("BUNDLE_IGNORE_CONFIG".to_string(), "1".to_string()),
        (
            "BUNDLE_GEMFILE".to_string(),
            project_dir.join("Gemfile").display().to_string(),
        ),
        ("BUNDLE_FROZEN".to_string(), "true".to_string()),
        ("BUNDLE_DISABLE_SHARED_GEMS".to_string(), "true".to_string()),
        ("BUNDLE_AUTO_INSTALL".to_string(), "false".to_string()),
        (
            "BUNDLE_DISABLE_VERSION_CHECK".to_string(),
            "true".to_string(),
        ),
        // Unsetting GEMRC would re-enable ~/.gemrc; point it at an empty
        // config instead (system /etc/gemrc remains a documented impurity).
        ("GEMRC".to_string(), "/dev/null".to_string()),
    ]
}

/// Env applied by `blanket run` for a projected ruby environment.
pub fn run_env(
    project_dir: &Path,
    gems_obj: &Path,
) -> (Vec<&'static str>, Vec<&'static str>, Vec<(String, String)>) {
    (
        ENV_REMOVE_PREFIXES.to_vec(),
        ENV_REMOVE.to_vec(),
        forced_env(project_dir, gems_obj),
    )
}

fn run_ruby(
    ruby_obj: &Path,
    cwd: &Path,
    gem_home: &Path,
    args: &[&str],
) -> io::Result<std::process::Output> {
    let mut cmd = Command::new(ruby_obj.join(format!("bin/{}", args[0])));
    cmd.args(&args[1..]).current_dir(cwd);
    // Ruby FIRST on PATH: a gem executable named ruby/gem must never shadow.
    let path = format!(
        "{}:{}",
        ruby_obj.join("bin").display(),
        std::env::var("PATH").unwrap_or_default()
    );
    cmd.env("PATH", path);
    force_env(
        &mut cmd,
        ENV_REMOVE_PREFIXES,
        ENV_REMOVE,
        &forced_env(cwd, gem_home),
    );
    cmd.stdin(std::process::Stdio::null());
    cmd.output()
        .map_err(|e| io::Error::new(e.kind(), format!("run store ruby {args:?}: {e}")))
}

/// Helper executed BY the pinned Ruby: parses the lock with Bundler's own
/// classes, validates the Gemfile/ruby directive, selects the local
/// platform's closure, and emits it dependency-first as JSON.
/// Second mode reads a downloaded .gem's spec for post-download checks.
const HELPER: &str = r##"
require "json"
mode = ARGV.shift
if mode == "install"
  # Direct Gem::Installer: the `gem install` CLI requires remote_fetcher at
  # LOAD time, which trips EPERM under the network-denied sandbox. This
  # path is offline-only code. wrappers: real wrapper scripts, NEVER
  # symlinks — symlink binstubs point into the staging dir and dangle
  # after the store commit rename (Sol review, reproduced).
  require "rubygems/installer"
  gemfile, install_dir = ARGV
  installer = Gem::Installer.at(
    gemfile,
    install_dir: install_dir,
    bin_dir: File.join(install_dir, "bin"),
    ignore_dependencies: true,
    document: [],
    wrappers: true,
    env_shebang: true
  )
  installer.install
  puts "installed #{File.basename(gemfile)}"
  exit 0
end
if mode == "check"
  # Gemfile/lock equivalence + ruby-version gate. This mode EVALS THE
  # GEMFILE (arbitrary ruby, delegated resolver trust): its stdout is
  # never parsed by blanket — only the exit status counts, so a hostile
  # Gemfile cannot forge plan data through this process.
  require "bundler"
  gemfile, lockfile = ARGV
  definition = Bundler::Definition.build(Pathname.new(gemfile), Pathname.new(lockfile), false)
  begin
    definition.send(:ensure_equivalent_gemfile_and_lockfile)
  rescue NoMethodError
    abort "store bundler cannot validate gemfile/lock equivalence"
  end
  begin
    definition.validate_runtime!
  rescue Bundler::GemNotFound, Bundler::SolveFailure
  rescue NotImplementedError, NoMethodError
  end
  exit 0
end
if mode == "spec"
  require "rubygems/package"
  spec = Gem::Package.new(ARGV[0]).spec
  puts({ "name" => spec.name, "version" => spec.version.to_s,
         "platform" => spec.platform.to_s,
         "executables" => spec.executables }.to_json)
  exit 0
end
abort "usage: helper plan <lockfile>" unless mode == "plan"
# LOCK-ONLY: this mode never evaluates the Gemfile (arbitrary ruby must
# not be able to forge artifact coordinates); the lockfile is the sole
# artifact authority (Sol review, forged-JSON repro).
require "bundler"
lockfile = ARGV[0]
lock = Bundler::LockfileParser.new(File.read(lockfile))
unless (lock.bundler_version rescue nil).nil?
  if Gem::Version.new(lock.bundler_version.to_s) > Gem::Version.new(Bundler::VERSION)
    abort "lockfile BUNDLED WITH #{lock.bundler_version} is newer than the store bundler #{Bundler::VERSION}"
  end
end
require "uri"
lock.specs.each do |s|
  src = s.source
  ok = src.is_a?(Bundler::Source::Rubygems) && src.remotes.all? do |r|
    u = URI.parse(r.to_s)
    u.scheme == "https" && u.host == "rubygems.org" && u.userinfo.nil? &&
      (u.port == 443) && ["", "/"].include?(u.path)
  end
  abort "unsupported source for #{s.name} (#{src.class}); only https://rubygems.org is supported" unless ok
end
local = Gem::Platform.local
selected = lock.specs.group_by(&:name).map do |name, specs|
  # Bundler's OWN best-platform scoring (arm64-darwin vs arm64-darwin-20
  # etc.); hand-rolled specificity picks the wrong artifact.
  best = Bundler::GemHelpers.select_best_platform_match(specs, local)
  best = Array(best)
  abort "#{name}: no variant for #{local} (have: #{specs.map { |s| s.platform.to_s }.uniq.join(", ")}); run: bundle lock --add-platform #{local}" if best.empty?
  best.first
end
# Bundler's parsed checksum registry (handles every format it writes).
# If a CHECKSUMS section exists but yields no usable sha256 for a
# selected gem, fail CLOSED rather than falling back to the live API.
has_checksums_section = File.read(lockfile).lines.any? { |l| l.chomp == "CHECKSUMS" }
checksums = {}
if has_checksums_section
  reg = (lock.respond_to?(:checksums) ? lock.checksums : nil)
  selected.each do |s|
    entry = nil
    if reg
      key = begin
        Bundler::LazySpecification.new(s.name, s.version, s.platform)
      rescue StandardError
        s
      end
      cs = (reg[key] rescue nil) || (reg[s] rescue nil)
      entry = Array(cs).flatten.find { |c| c.respond_to?(:algo) && c.algo == "sha256" } rescue nil
    end
    hexval = nil
    if entry
      begin
        raw = entry.respond_to?(:digest) ? entry.digest : nil
        hexval = raw.unpack1("H*") if raw
        hexval ||= entry.to_s[/sha256[-=]([A-Za-z0-9+\/=]+)/, 1]&.unpack1("m0")&.unpack1("H*") rescue nil
      rescue StandardError
      end
    end
    abort "#{s.name}: CHECKSUMS section present but no usable sha256 for #{s.name}-#{s.version}; refusing API fallback" if hexval.nil?
    plat = s.platform.to_s
    checksums["#{s.name}-#{s.version}#{plat == "ruby" ? "" : "-#{plat}"}"] = hexval
  end
end
by_name = selected.to_h { |s| [s.name, s] }
ordered = []
state = {}
visit = lambda do |s|
  case state[s.name]
  when :done then next
  when :visiting then next # cycle: break arbitrarily, install order best-effort
  end
  state[s.name] = :visiting
  s.dependencies.each do |d|
    dep = by_name[d.name]
    visit.call(dep) if dep
  end
  state[s.name] = :done
  ordered << s
end
selected.each { |s| visit.call(s) }
out = ordered.map do |s|
  plat = s.platform.to_s
  full = plat == "ruby" ? "#{s.name}-#{s.version}" : "#{s.name}-#{s.version}-#{plat}"
  { "name" => s.name, "version" => s.version.to_s, "platform" => plat,
    "full_name" => full,
    "checksum" => checksums["#{s.name}-#{s.version}#{plat == "ruby" ? "" : "-#{plat}"}"] }
end
puts({ "ruby_platform" => local.to_s, "bundler" => Bundler::VERSION,
       "gems" => out }.to_json)
"##;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RubyGem {
    pub name: String,
    pub version: String,
    pub platform: String,
    pub full_name: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RubyPlan {
    pub ruby_version: String,
    pub ruby_platform: String,
    pub bundler_version: String,
    pub gems: Vec<RubyGem>,
}

fn valid_component(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        && !s.starts_with('.')
}

fn validate_plan(plan: &RubyPlan) -> io::Result<()> {
    let mut seen = std::collections::BTreeSet::new();
    for g in &plan.gems {
        if !valid_component(&g.name)
            || !valid_component(&g.version)
            || !(g.platform == "ruby" || valid_component(&g.platform))
            || !valid_component(&g.full_name)
        {
            return Err(err(format!("invalid gem coordinates in plan: {g:?}")));
        }
        if g.sha256.len() != 64 || !g.sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(err(format!("{}: invalid sha256 in plan", g.full_name)));
        }
        if !seen.insert(g.name.clone()) {
            return Err(err(format!("duplicate gem {} in plan", g.name)));
        }
    }
    Ok(())
}

/// Plan the gem closure: Bundler-delegated lock parsing + platform
/// selection, blanket-pinned hashes (lock CHECKSUMS section when present,
/// rubygems.org v2 API otherwise). Cached in .blanket/ruby-plan.json.
pub fn plan_ruby(
    store: &Store,
    project_dir: &Path,
    ruby_obj: &Path,
) -> io::Result<(RubyPlan, String)> {
    if !project_dir.join("Gemfile").is_file() {
        return Err(err("Gemfile not found"));
    }
    let lock_path = project_dir.join("Gemfile.lock");
    if !lock_path.is_file() {
        eprintln!("blanket: no Gemfile.lock; resolving with the store bundler...");
        let scratch = store.stage()?;
        let out = run_ruby(ruby_obj, project_dir, &scratch, &["bundle", "lock"])?;
        let _ = crate::store::remove_tree(&scratch);
        if !out.status.success() {
            return Err(err(format!(
                "store bundle lock failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
    }
    let lock = fs::read_to_string(&lock_path)?;
    // No plan cache: an editable cache with a predictable key is forgeable
    // authority (Sol review 5). Planning re-derives from the lock every
    // sync; the store's object cache still makes realizes instant.

    let scratch = store.stage()?;
    let helper = scratch.join("helper.rb");
    fs::write(&helper, HELPER)?;
    let helper_path = helper
        .to_str()
        .ok_or_else(|| err("helper path not UTF-8"))?;
    // Gate 1: Gemfile/lock equivalence + ruby directive. EVALS THE GEMFILE
    // (delegated resolver trust) — exit status only, stdout untrusted.
    let out = run_ruby(
        ruby_obj,
        project_dir,
        &scratch,
        &[
            "ruby",
            helper_path,
            "check",
            project_dir
                .join("Gemfile")
                .to_str()
                .ok_or_else(|| err("path not UTF-8"))?,
            lock_path.to_str().ok_or_else(|| err("path not UTF-8"))?,
        ],
    )?;
    if !out.status.success() {
        let _ = crate::store::remove_tree(&scratch);
        return Err(err(format!(
            "Gemfile/Gemfile.lock validation failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    // Gate 2: LOCK-ONLY closure derivation (never evaluates the Gemfile).
    let out = run_ruby(
        ruby_obj,
        project_dir,
        &scratch,
        &[
            "ruby",
            helper_path,
            "plan",
            lock_path.to_str().ok_or_else(|| err("path not UTF-8"))?,
        ],
    )?;
    let _ = crate::store::remove_tree(&scratch);
    if !out.status.success() {
        return Err(err(format!(
            "bundler lock analysis failed: {}{}",
            String::from_utf8_lossy(&out.stderr).trim(),
            String::from_utf8_lossy(&out.stdout).trim()
        )));
    }
    #[derive(Deserialize)]
    struct HelperGem {
        name: String,
        version: String,
        platform: String,
        full_name: String,
        checksum: Option<String>,
    }
    #[derive(Deserialize)]
    struct HelperOut {
        ruby_platform: String,
        bundler: String,
        gems: Vec<HelperGem>,
    }
    let parsed: HelperOut =
        serde_json::from_slice(&out.stdout).map_err(|e| err(format!("helper output: {e}")))?;

    let mut gems = Vec::new();
    for g in parsed.gems {
        let sha256 = match g.checksum {
            Some(c) => c,
            None => {
                // ALWAYS platform-qualified: the bare endpoint returns the
                // latest-PUSHED variant (racc 1.8.1 returns the java gem's
                // sha!). Validate the reply's platform too.
                let url = format!(
                    "https://rubygems.org/api/v2/rubygems/{}/versions/{}.json?platform={}",
                    g.name, g.version, g.platform
                );
                let body = ureq::get(&url)
                    .call()
                    .map_err(|e| err(format!("{}: {url}: {e}", g.full_name)))?
                    .into_string()
                    .map_err(|e| err(format!("{}: read: {e}", g.full_name)))?;
                let v: serde_json::Value = serde_json::from_str(&body)
                    .map_err(|e| err(format!("{}: api json: {e}", g.full_name)))?;
                if v["number"].as_str() != Some(g.version.as_str())
                    || v["platform"].as_str() != Some(g.platform.as_str())
                {
                    return Err(err(format!(
                        "{}: api returned {}-{} instead",
                        g.full_name, v["number"], v["platform"]
                    )));
                }
                v["sha"]
                    .as_str()
                    .ok_or_else(|| err(format!("{}: api has no sha", g.full_name)))?
                    .to_string()
            }
        };
        gems.push(RubyGem {
            name: g.name,
            version: g.version,
            platform: g.platform,
            full_name: g.full_name,
            sha256,
        });
    }
    let plan = RubyPlan {
        ruby_version: RUBY_VERSION.to_string(),
        ruby_platform: parsed.ruby_platform,
        bundler_version: parsed.bundler,
        gems,
    };
    validate_plan(&plan)?;
    // Snapshot guard: the lock this plan derives from is the lock whose
    // digest provenance will record (Go precedent).
    let now = fs::read_to_string(&lock_path)?;
    if now != lock {
        return Err(err(
            "Gemfile.lock changed while planning; re-run blanket sync",
        ));
    }
    Ok((plan, hex::encode(Sha256::digest(lock.as_bytes()))))
}

/// Realize the immutable GEM_HOME object: dependency-first sandboxed
/// installs (native extensions compile here, network denied).
pub fn realize_gems(
    store: &Store,
    platform: Platform,
    plan: &RubyPlan,
    ruby_obj: &Path,
) -> io::Result<PathBuf> {
    crate::platform::require_host(platform, "Ruby gems", "stage 4")?;
    let pin = ruby_pin(platform)?;
    validate_plan(plan)?;
    let identity = ruby_gems_identity(pin, plan);
    let id = identity.object_id();
    if store.has(&id) {
        crate::policy::check_cached(store, &id)?;
        return Ok(store.object_path(&id));
    }

    // Fetch + post-download spec verification first (all-or-nothing).
    let scratch = store.stage()?;
    let helper = scratch.join("helper.rb");
    fs::write(&helper, HELPER)?;
    let mut artifacts: Vec<(&RubyGem, PathBuf)> = Vec::new();
    let mut executables: BTreeMap<String, String> = BTreeMap::new();
    for g in &plan.gems {
        let url = format!("https://rubygems.org/downloads/{}.gem", g.full_name);
        let file = download_verified(store, &url, &g.sha256).map_err(|e| {
            io::Error::new(e.kind(), format!("{}: {e}", g.full_name))
        })?;
        let out = run_ruby(
            ruby_obj,
            &scratch,
            &scratch,
            &[
                "ruby",
                helper.to_str().unwrap(),
                "spec",
                file.to_str().ok_or_else(|| err("gem path not UTF-8"))?,
            ],
        )?;
        if !out.status.success() {
            return Err(err(format!(
                "{}: gemspec read failed: {}",
                g.full_name,
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        let spec: serde_json::Value = serde_json::from_slice(&out.stdout)
            .map_err(|e| err(format!("{}: spec json: {e}", g.full_name)))?;
        let canonical = if g.platform == "ruby" {
            format!("{}-{}", g.name, g.version)
        } else {
            format!("{}-{}-{}", g.name, g.version, g.platform)
        };
        if spec["name"].as_str() != Some(g.name.as_str())
            || spec["version"].as_str() != Some(g.version.as_str())
            || spec["platform"].as_str() != Some(g.platform.as_str())
            || g.full_name != canonical
        {
            return Err(err(format!(
                "{}: embedded gemspec disagrees with the plan ({} {} {})",
                g.full_name, spec["name"], spec["version"], spec["platform"]
            )));
        }
        if let Some(exes) = spec["executables"].as_array() {
            for e in exes {
                if let Some(e) = e.as_str() {
                    if let Some(prev) = executables.insert(e.to_string(), g.name.clone()) {
                        return Err(err(format!(
                            "executable {e:?} provided by both {prev} and {}; refusing \
                             ambiguous bin dir",
                            g.name
                        )));
                    }
                }
            }
        }
        artifacts.push((g, file));
    }

    let staged = store.stage()?;
    let bin = staged.join("bin");
    fs::create_dir_all(&bin)?;
    for (g, file) in &artifacts {
        // gem install only treats .gem-named arguments as local files (the
        // same lesson as pip and sdists); COPY from the cache, never link.
        let named = scratch.join(format!("{}.gem", g.full_name));
        fs::copy(file, &named)?;
        // Dependency-first order comes from the plan (helper topo-sort):
        // extconf.rb may require already-installed dependency gems.
        let spec = BuildSpec {
            argv: vec![
                ruby_obj.join("bin/ruby").display().to_string(),
                helper.display().to_string(),
                "install".to_string(),
                named.display().to_string(),
                staged.display().to_string(),
            ],
            cwd: scratch.clone(),
            env: vec![
                ("GEM_HOME".to_string(), staged.display().to_string()),
                ("GEM_PATH".to_string(), staged.display().to_string()),
                ("BUNDLE_IGNORE_CONFIG".to_string(), "1".to_string()),
            ],
            read: vec![ruby_obj.to_path_buf()],
            write: vec![staged.clone()],
            scratch: scratch.clone(),
            path: format!("{}:/usr/bin:/bin", ruby_obj.join("bin").display()),
        };
        crate::sandbox::run_build_spec_on(platform, &spec).map_err(|e| {
            io::Error::new(e.kind(), format!(
                "{}: sandboxed gem install failed: {e}\n(network is denied; \
                 gems whose installers need network or missing host \
                 libraries are unsupported in v0)",
                g.full_name
            ))
        })?;
    }
    let _ = crate::store::remove_tree(&scratch);
    store.commit(&identity, &staged, &[]).map(|(path, _)| path)
}

/// Project provenance (closure envelope); enforcement is env, set at run.
pub fn project_ruby_env(
    project_dir: &Path,
    ruby_obj: &Path,
    gems_obj: &Path,
    plan: &RubyPlan,
    lock_sha256: &str,
) -> io::Result<()> {
    let object_ref = |path: &Path| -> io::Result<serde_json::Value> {
        let id = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| err(format!("object path has no UTF-8 id: {}", path.display())))?;
        Ok(serde_json::json!({"path": path.display().to_string(), "id": id}))
    };
    crate::project::write_closure(
        project_dir,
        "ruby",
        serde_json::json!({
            "ruby_object": object_ref(&ruby_obj.canonicalize()?)?,
            "gems_object": object_ref(&gems_obj.canonicalize()?)?,
            "gemfile_lock_sha256": lock_sha256,
            "plan": plan,
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "blanket-ruby-unit-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = crate::store::remove_tree(&self.0);
        }
    }

    #[test]
    fn ruby_pins_cover_supported_platforms() {
        assert_eq!(RUBY_PINS.len(), Platform::ALL.len());
        for platform in Platform::ALL {
            assert_eq!(ruby_pin(*platform).unwrap().platform, *platform);
        }
        let linux = ruby_pin(Platform::X86_64UnknownLinuxGnu).unwrap();
        assert_eq!(linux.url, "https://github.com/Homebrew/homebrew-portable-ruby/releases/download/3.4.6/portable-ruby-3.4.6.x86_64_linux.bottle.tar.gz");
        assert_eq!(
            linux.sha256,
            "40932a3950ccc8bf9d13d98e692e5518427cc66b4f9520956cec349629d25259"
        );
    }

    fn linux_test_plan() -> RubyPlan {
        RubyPlan {
            ruby_version: RUBY_VERSION.into(),
            ruby_platform: "x86_64-linux".into(),
            bundler_version: "2.6.9".into(),
            gems: vec![RubyGem {
                name: "rake".into(),
                version: "13.2.1".into(),
                platform: "ruby".into(),
                full_name: "rake-13.2.1".into(),
                sha256: "a".repeat(64),
            }],
        }
    }

    #[test]
    fn linux_and_darwin_identities_are_distinct_rows_of_one_schema() {
        let darwin_pin = ruby_pin(Platform::Aarch64AppleDarwin).unwrap();
        let linux_pin = ruby_pin(Platform::X86_64UnknownLinuxGnu).unwrap();
        let darwin = ruby_identity(darwin_pin);
        let linux = ruby_identity(linux_pin);
        assert_ne!(darwin.object_id(), linux.object_id());
        // Same input keys: the Linux pin is a row, not a second recipe.
        assert_eq!(
            darwin.inputs.keys().collect::<Vec<_>>(),
            linux.inputs.keys().collect::<Vec<_>>()
        );
        assert_eq!(linux.inputs["platform"], "x86_64-unknown-linux-gnu");
        assert_eq!(linux.inputs["artifact_sha256"], linux_pin.sha256);

        let plan = linux_test_plan();
        let darwin_gems = ruby_gems_identity(darwin_pin, &plan);
        let linux_gems = ruby_gems_identity(linux_pin, &plan);
        assert_ne!(darwin_gems.object_id(), linux_gems.object_id());
        assert!(linux_gems.inputs["installer"].contains(linux_pin.sha256));
    }

    #[test]
    fn linux_identities_pinned() {
        // Goldens for the shared-store check (LINUX_PORT.md stage 6): a Mac
        // and a Linux box realizing the same pin must not collide, and the
        // Linux ids must not drift without a deliberate identity change.
        let pin = ruby_pin(Platform::X86_64UnknownLinuxGnu).unwrap();
        assert_eq!(
            (
                ruby_identity(pin).object_id(),
                ruby_gems_identity(pin, &linux_test_plan()).object_id(),
            ),
            (
                "192a4c7b501dd09eb3c76a3ebd427e8077fbda6e-ruby-3.4.6".to_string(),
                "ee94737d938d41b8454fd6ea7d75dc737ccf73e5-gems-1".to_string(),
            )
        );
    }

    #[test]
    fn synthetic_bottle_uses_two_root_components_and_validates_layout() {
        let temp = TempDir::new();
        let source = temp.0.join("source with spaces");
        let tree = source.join("portable-ruby/3.4.6");
        fs::create_dir_all(tree.join("bin")).unwrap();
        fs::create_dir_all(tree.join("lib")).unwrap();
        fs::create_dir_all(tree.join("include/ruby-3.4.0")).unwrap();
        fs::write(tree.join("bin/ruby"), b"#!/bin/sh\n").unwrap();
        fs::write(tree.join("bin/gem-real"), b"#!/bin/sh\n").unwrap();
        symlink("gem-real", tree.join("bin/gem")).unwrap();
        fs::write(tree.join("bin/bundle"), b"#!/bin/sh\n").unwrap();
        fs::write(tree.join("lib/libruby-3.4.so"), b"ELF\0not text").unwrap();
        fs::write(tree.join("include/ruby-3.4.0/ruby.h"), b"#define RUBY_H 1\n").unwrap();
        fs::set_permissions(tree.join("bin/ruby"), fs::Permissions::from_mode(0o755))
            .unwrap();

        let archive = temp.0.join("portable ruby.tar.gz");
        let status = Command::new("/usr/bin/tar")
            .args(["-czf"])
            .arg(&archive)
            .args(["-C"])
            .arg(&source)
            .arg("portable-ruby")
            .status()
            .unwrap();
        assert!(status.success());

        let staged = temp.0.join("staged");
        fs::create_dir(&staged).unwrap();
        extract_ruby_bottle(&archive, &staged).unwrap();
        assert!(staged.join("bin/ruby").is_file());
        assert!(staged.join("bin/gem").is_symlink());
        assert!(!staged.join("portable-ruby").exists());
        assert_eq!(
            fs::metadata(staged.join("bin/ruby"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o755
        );

        fs::remove_file(staged.join("bin/bundle")).unwrap();
        let error = validate_ruby_layout(&staged).unwrap_err();
        assert!(error.to_string().contains("Bundler launcher"));
    }

    #[test]
    fn darwin_identity_unchanged() {
        let platform = Platform::Aarch64AppleDarwin;
        let pin = ruby_pin(platform).unwrap();
        let identity = ruby_identity(pin);
        assert_eq!(
            identity.object_id(),
            "c4c2411b7540521f48dcdd8cff25786e261ed1ee-ruby-3.4.6"
        );
    }

    #[test]
    fn darwin_ruby_gems_identity_unchanged() {
        let pin = ruby_pin(Platform::Aarch64AppleDarwin).unwrap();
        let plan = RubyPlan {
            ruby_version: RUBY_VERSION.into(),
            ruby_platform: "arm64-darwin20".into(),
            bundler_version: "2.6.9".into(),
            gems: vec![RubyGem {
                name: "rake".into(),
                version: "13.2.1".into(),
                platform: "ruby".into(),
                full_name: "rake-13.2.1".into(),
                sha256: "a".repeat(64),
            }],
        };
        let identity = ruby_gems_identity(pin, &plan);
        assert_eq!(
            identity.object_id(),
            "c017bc4da37483c7d35d1997df4c541d35e4a751-gems-1"
        );
    }

    #[test]
    fn plan_validation_rejects_hostile_fields() {
        let base = RubyGem {
            name: "rake".into(),
            version: "13.2.1".into(),
            platform: "ruby".into(),
            full_name: "rake-13.2.1".into(),
            sha256: "a".repeat(64),
        };
        let ok = RubyPlan {
            ruby_version: RUBY_VERSION.into(),
            ruby_platform: "arm64-darwin20".into(),
            bundler_version: "2.6.9".into(),
            gems: vec![base.clone()],
        };
        assert!(validate_plan(&ok).is_ok());
        let mut evil = base.clone();
        evil.full_name = "../escape".into();
        assert!(validate_plan(&RubyPlan {
            gems: vec![evil],
            ..ok.clone()
        })
        .is_err());
        let mut bad = base.clone();
        bad.sha256 = "zz".into();
        assert!(validate_plan(&RubyPlan {
            gems: vec![bad],
            ..ok.clone()
        })
        .is_err());
        let dup = RubyPlan {
            gems: vec![base.clone(), base.clone()],
            ..ok.clone()
        };
        assert!(validate_plan(&dup).is_err());
    }

    #[test]
    fn linux_plan_accepts_source_and_platform_qualified_gems() {
        let plan = RubyPlan {
            ruby_version: RUBY_VERSION.into(),
            ruby_platform: "x86_64-linux".into(),
            bundler_version: "2.6.9".into(),
            gems: vec![
                RubyGem {
                    name: "mini_portile2".into(),
                    version: "2.8.9".into(),
                    platform: "ruby".into(),
                    full_name: "mini_portile2-2.8.9".into(),
                    sha256: "a".repeat(64),
                },
                RubyGem {
                    name: "nokogiri".into(),
                    version: "1.18.10".into(),
                    platform: "x86_64-linux".into(),
                    full_name: "nokogiri-1.18.10-x86_64-linux".into(),
                    sha256: "b".repeat(64),
                },
            ],
        };
        assert!(validate_plan(&plan).is_ok());
    }

    #[test]
    fn forced_env_covers_bundler_side_doors() {
        let env = forced_env(Path::new("/p"), Path::new("/g"));
        let keys: Vec<&str> = env.iter().map(|(k, _)| k.as_str()).collect();
        for required in [
            "BUNDLE_IGNORE_CONFIG",
            "BUNDLE_GEMFILE",
            "BUNDLE_FROZEN",
            "GEM_HOME",
            "GEM_PATH",
        ] {
            assert!(keys.contains(&required), "{required}");
        }
        assert!(ENV_REMOVE.contains(&"RUBYOPT"));
        assert!(ENV_REMOVE.contains(&"RUBYLIB"));
        assert!(ENV_REMOVE_PREFIXES.contains(&"BUNDLE_"));
    }
}

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

const RUBY_VERSION: &str = "3.4.6";
// Homebrew portable-ruby: relocatable, bundler included; the ruby Homebrew
// itself ships on. Newest PORTABLE artifact (ruby-lang 3.4.x source may be
// newer; documented gap until a newer portable build exists).
const RUBY_URL: &str = "https://github.com/Homebrew/homebrew-portable-ruby/releases/download/3.4.6/portable-ruby-3.4.6.arm64_big_sur.bottle.tar.gz";
const RUBY_SHA256: &str = "62fe925f284cc38aac68b9a42b02cd90de753f8832e8866be3fd60558dd70f67";

fn err(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

/// Ensure the pinned portable Ruby is realized (interpreter at <obj>/bin/ruby).
pub fn ensure_ruby(store: &Store) -> io::Result<PathBuf> {
    let identity = Identity {
        kind: "ruby".into(),
        name: "ruby".into(),
        version: RUBY_VERSION.into(),
        inputs: BTreeMap::from([
            ("schema".to_string(), "ruby-toolchain/1".to_string()),
            ("artifact_sha256".to_string(), RUBY_SHA256.to_string()),
            ("platform".to_string(), "aarch64-apple-darwin".to_string()),
        ]),
    };
    let id = identity.object_id();
    if store.has(&id) {
        return Ok(store.object_path(&id));
    }
    let tarball = download_verified(store, RUBY_URL, RUBY_SHA256)?;
    let staged = store.stage()?;
    // Bottle layout: portable-ruby/3.4.6/<tree> — strip 2.
    let status = Command::new("/usr/bin/tar")
        .args(["-xzf"])
        .arg(&tarball)
        .args(["-C"])
        .arg(&staged)
        .args(["--strip-components", "2"])
        .status()?;
    if !status.success() || !staged.join("bin/ruby").is_file() {
        return Err(err("portable-ruby extraction failed or has unexpected layout"));
    }
    store.commit(&identity, &staged)
}

/// The forced environment for EVERY blanket-controlled ruby/bundler run.
/// Removal lists close the .bundle/config and preload side doors.
const ENV_REMOVE_PREFIXES: &[&str] = &["BUNDLE_", "BUNDLER_"];
const ENV_REMOVE: &[&str] = &["RUBYOPT", "RUBYLIB", "RUBYGEMS_GEMDEPS", "GEM_SPEC_CACHE", "GEM_HOME", "GEM_PATH"];

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
        ("BUNDLE_DISABLE_VERSION_CHECK".to_string(), "true".to_string()),
        // Unsetting GEMRC would re-enable ~/.gemrc; point it at an empty
        // config instead (system /etc/gemrc remains a documented impurity).
        ("GEMRC".to_string(), "/dev/null".to_string()),
    ]
}

/// Env applied by `blanket run` for a projected ruby environment.
pub fn run_env(project_dir: &Path, gems_obj: &Path) -> (Vec<&'static str>, Vec<&'static str>, Vec<(String, String)>) {
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
    force_env(&mut cmd, ENV_REMOVE_PREFIXES, ENV_REMOVE, &forced_env(cwd, gem_home));
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
        if !valid_component(&g.name) || !valid_component(&g.version)
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
    let helper_path = helper.to_str().ok_or_else(|| err("helper path not UTF-8"))?;
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
            project_dir.join("Gemfile").to_str().ok_or_else(|| err("path not UTF-8"))?,
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
    let parsed: HelperOut = serde_json::from_slice(&out.stdout)
        .map_err(|e| err(format!("helper output: {e}")))?;

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
        return Err(err("Gemfile.lock changed while planning; re-run blanket sync"));
    }
    Ok((plan, hex::encode(Sha256::digest(lock.as_bytes()))))
}

/// Realize the immutable GEM_HOME object: dependency-first sandboxed
/// installs (native extensions compile here, network denied).
pub fn realize_gems(store: &Store, plan: &RubyPlan, ruby_obj: &Path) -> io::Result<PathBuf> {
    validate_plan(plan)?;
    let mut inputs = BTreeMap::from([
        ("schema".to_string(), "ruby-gems/1".to_string()),
        // Installer recipe AND wrapper-byte provenance: generated binstubs
        // embed interpreter paths.
        (
            "installer".to_string(),
            format!("ruby{RUBY_VERSION}:{RUBY_SHA256}"),
        ),
        ("ruby_platform".to_string(), plan.ruby_platform.clone()),
    ]);
    for g in &plan.gems {
        inputs.insert(format!("gem:{}", g.full_name), g.sha256.clone());
    }
    let identity = Identity {
        kind: "ruby-gems".into(),
        name: "gems".into(),
        version: plan.gems.len().to_string(),
        inputs,
    };
    let id = identity.object_id();
    if store.has(&id) {
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
        let file = download_verified(store, &url, &g.sha256)
            .map_err(|e| err(format!("{}: {e}", g.full_name)))?;
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
        run_build_spec(&spec).map_err(|e| {
            err(format!(
                "{}: sandboxed gem install failed: {e}\n(network is denied; \
                 gems whose installers need network or missing host \
                 libraries are unsupported in v0)",
                g.full_name
            ))
        })?;
    }
    let _ = crate::store::remove_tree(&scratch);
    store.commit(&identity, &staged)
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
        assert!(validate_plan(&RubyPlan { gems: vec![evil], ..ok.clone() }).is_err());
        let mut bad = base.clone();
        bad.sha256 = "zz".into();
        assert!(validate_plan(&RubyPlan { gems: vec![bad], ..ok.clone() }).is_err());
        let dup = RubyPlan {
            gems: vec![base.clone(), base.clone()],
            ..ok.clone()
        };
        assert!(validate_plan(&dup).is_err());
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

//! The Ruby tailor: Bundler-delegated planning, tog-verified gems,
//! immutable GEM_HOME objects, sandboxed native-extension installs.
//!
//! Platform selection and lock parsing are DELEGATED to the pinned Ruby's
//! own Bundler/RubyGems (a helper script —
//! Gem::Platform matching has wildcards and specificity scores no hand
//! parser should reimplement), while every artifact byte is still pinned
//! and verified by tog. Bundler's local .bundle/config outranks plain
//! env vars, so every tog-controlled invocation scrubs BUNDLE_*/RUBY*
//! preload vars and sets BUNDLE_IGNORE_CONFIG=1.

mod door;
pub mod edit;
mod gem_home;
mod native;
mod native_libs;
pub mod objects;
pub(crate) mod registry;
mod resolve;
pub mod tailor;
mod unpack;

pub(crate) use door::ruby_tool;
pub use resolve::{attest_project, generate_lock};

use unpack::extract_ruby_bottle;
#[cfg(test)]
use unpack::extract_ruby_bottle_for_test;

use crate::kernel::activity::StoreActivity;
use crate::kernel::digest::Algo;
use crate::kernel::fetch::{
    download_toolchain_artifact_held, download_verified_held, hash_file, CacheLease, Digest,
};
use crate::kernel::fsroot::ProjectRoot;
use crate::kernel::platform::Platform;
use crate::kernel::resolve::{DelegateSpec, ResolutionDoor};
use crate::kernel::sandbox::{BuildSpec, HostView};
use crate::kernel::store::Store;
use crate::kernel::toolchain::document::Shipped;
use crate::kernel::toolchain::{ArtifactRow, Catalog, Selected};
use crate::kernel::types::Identity;
use crate::kernel::ui;
use native::{
    cached_gems_object, record_host_fallback, ruby_gems_fallback_identity, same_host_state,
    GemInstall, RUNTIME_ONLY_VIEW,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

// Homebrew portable-ruby: relocatable, bundler included; the ruby Homebrew
// itself ships on. The catalog holds every portable build of the ruby-lang
// lines still maintained (ruby-lang source may be newer; documented gap
// until a newer portable build exists).
//
// Both 3.4.6 bottles were inspected: root `portable-ruby/3.4.6/`,
// no symlinks, `#!/bin/sh` wrappers that `exec "$bindir/ruby"` relative to
// $0, `--enable-load-relative` (RbConfig prefix follows the object path) and
// `--with-static-linked-ext` (openssl/zlib/yaml/ffi compiled into
// `bin/ruby`). The Linux binary's NEEDED set is glibc only; its RUNPATH still
// lists `/home/linuxbrew/...` build directories but nothing NEEDED lives
// there, so it is inert provenance (like `configure_args`) and is NOT
// rewritten: no staging repair, hence no relocation-recipe identity input.
// RubyGems reports `Gem::Platform.local` = `x86_64-linux` for that bottle,
// which is neither the bottle tag (`x86_64_linux`) nor the Rust triple; the
// plan records whatever the pinned interpreter says. The generator checks
// every bottle it adds for the same layout (one `portable-ruby/<tag>/` root,
// no link leaving it, the entries `validate_ruby_layout` requires).
static CATALOG: Shipped = Shipped::new(include_str!("catalog.toml"));

/// The default Ruby's bottle for a platform: what a project with no Ruby
/// pin realizes there.
fn ruby_pin(platform: Platform) -> io::Result<&'static ArtifactRow> {
    CATALOG.default_row(platform, "ruby")
}

/// The shipped Ruby catalog: one release bundle per portable-ruby build,
/// generated and verified by `tools/catalog.py ruby`, and its default.
pub fn toolchain_catalog() -> io::Result<Catalog> {
    CATALOG.catalog()
}

pub fn preflight_platform(platform: Platform) -> io::Result<()> {
    crate::kernel::platform::require_host(platform, "Ruby")?;
    ruby_pin(platform).map(|_| ())
}

/// The recipe this tailor knows how to build a Ruby object from. A lock
/// naming any other recipe was written by a tog that builds Ruby some other
/// way, and this one must not guess.
const RUBY_RECIPE: &str = "ruby-toolchain/1";

/// One Ruby realization's bytes, read from the selected toolchain rather
/// than from the compiled pin table: the same fields a pin carries, owned,
/// so a project's lock can supply them.
#[derive(Debug)]
struct RubySpec {
    platform: Platform,
    version: String,
    provider: String,
    url: String,
    sha256: String,
}

/// The selected Ruby's row for `platform`, refused unless this tog knows
/// the recipe that produced it.
fn ruby_spec(platform: Platform, selected: &Selected) -> io::Result<RubySpec> {
    selected.require("ruby", "ruby")?;
    let row = selected.checked_artifact(platform, "ruby", RUBY_RECIPE, "sha256")?;
    Ok(RubySpec {
        platform,
        version: row.version,
        provider: row.provider,
        url: row.url,
        sha256: row.digest.hex().to_string(),
    })
}

#[cfg(test)]
/// The shipped catalog's Ruby, for callers with no project selection to
/// honor. Inside a project every caller realizes from the lock instead.
fn shipped_selection() -> io::Result<Selected> {
    crate::kernel::toolchain::shipped(&toolchain_catalog()?)
}

fn ruby_identity(spec: &RubySpec) -> Identity {
    Identity {
        kind: "ruby".into(),
        name: "ruby".into(),
        version: spec.version.clone(),
        inputs: BTreeMap::from([
            ("schema".to_string(), "ruby-toolchain/1".to_string()),
            ("artifact_sha256".to_string(), spec.sha256.clone()),
            ("platform".to_string(), spec.platform.triple().to_string()),
        ]),
    }
}

/// `native_libs_id` is the pinned native library set the plan's native
/// gems build with (`native_libs::identity_id`): Linux only.
fn ruby_gems_identity(spec: &RubySpec, plan: &RubyPlan, native_libs_id: Option<&str>) -> Identity {
    let mut inputs = BTreeMap::from([
        ("schema".to_string(), "ruby-gems/1".to_string()),
        // Installer recipe AND wrapper-byte provenance: generated binstubs
        // embed interpreter paths.
        (
            "installer".to_string(),
            format!("ruby{}:{}", spec.version, spec.sha256),
        ),
        ("ruby_platform".to_string(), plan.ruby_platform.clone()),
    ]);
    // On Linux, native extensions compile against the host's C runtime
    // alone (`HostView::RuntimeOnly`; pure-Ruby gems compile nothing and
    // install against the full view), so the headers and libraries a build
    // sees are the same on every host with the same C runtime. A gem that
    // needs more falls back to the whole host, records `host-build-inputs`,
    // and the object is committed under `ruby_gems_fallback_identity`
    // instead, never under this id. Darwin builds see the whole SDK, and
    // their ids are pinned.
    //
    // Linux native gems also build with tog's pinned native library set
    // mounted (`native_libs`, #329). `native` spells out that decision
    // either way, so a dropped `native_libs` input cannot pass for a plan
    // with no native gem.
    if !spec.platform.is_macos() {
        inputs.insert("build_view".to_string(), RUNTIME_ONLY_VIEW.to_string());
        let native = match native_libs_id {
            Some(id) => {
                inputs.insert("native_libs".to_string(), id.to_string());
                native_libs::NATIVE_LIBS_MOUNTED
            }
            None => native_libs::NATIVE_NONE,
        };
        inputs.insert("native".to_string(), native.to_string());
    }
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

/// Realize the Ruby the selection names: its bytes, its version, its
/// digest. A catalog refresh cannot move a project's interpreter, because
/// nothing here reads the pin table.
pub fn realize_runtime(
    store: &Store,
    activity: &StoreActivity,
    platform: Platform,
    selected: &Selected,
) -> io::Result<PathBuf> {
    crate::tailors::install_kinds();
    crate::kernel::platform::require_host(platform, "Ruby")?;
    let spec = ruby_spec(platform, selected)?;
    let identity = ruby_identity(&spec);
    let id = identity.object_id();
    if store.has_with_activity(activity, &id)? {
        crate::kernel::policy::check_cached_with_activity(store, activity, &id)?;
        return Ok(store.object_path(&id));
    }
    let tarball = download_toolchain_artifact_held(
        store,
        activity,
        &spec.provider,
        &spec.url,
        &Digest::sha256(&spec.sha256)?,
    )?;
    let staged = store.stage_with_activity(activity)?;
    if let Err(error) = extract_ruby_bottle(activity, &tarball, &staged) {
        let _ = crate::kernel::store::remove_tree(&staged);
        return Err(error);
    }
    store
        .commit_with_activity_and_deps(activity, &identity, &staged, &[], &{
            let mut deps = crate::kernel::store::ObjectDeps::new();
            deps.cache_digest(Digest::sha256(&spec.sha256)?);
            deps
        })
        .map(|(path, _)| path)
}

/// The forced environment for EVERY tog-controlled ruby/bundler run.
/// Removal lists close the .bundle/config and preload side doors; they live
/// with the host-local tripwire, which checks the `spec` read by them.
const ENV_REMOVE_PREFIXES: &[&str] = crate::kernel::resolve::tripwire::RUBY_ENV_REMOVE_PREFIXES;
const ENV_REMOVE: &[&str] = crate::kernel::resolve::tripwire::RUBY_ENV_REMOVE;

/// The Gemfile and its lock as tog's delegates name them: relative to the
/// held project directory they start in.
const GEMFILE: &str = "Gemfile";
const GEMFILE_LOCK: &str = "Gemfile.lock";

/// The gem environment every store Ruby run shares: `gem_home` is the one
/// gem path, so neither the host's `~/.gem` nor its `GEM_PATH` is searched.
fn gem_env(gem_home: &Path) -> Vec<(String, String)> {
    vec![
        ("GEM_HOME".to_string(), gem_home.display().to_string()),
        ("GEM_PATH".to_string(), gem_home.display().to_string()),
        // Unsetting GEMRC would re-enable ~/.gemrc; point it at an empty
        // config instead (system /etc/gemrc remains a documented impurity).
        ("GEMRC".to_string(), "/dev/null".to_string()),
    ]
}

/// The environment every store Ruby tool runs with. `gemfile` is what
/// Bundler reads: tog's own delegates start inside the held project
/// directory and name it relatively, so a directory swapped in at the
/// project's path is never the one evaluated (#499).
fn forced_env(gemfile: &str, gem_home: &Path) -> Vec<(String, String)> {
    let mut env = gem_env(gem_home);
    env.extend([
        ("BUNDLE_IGNORE_CONFIG".to_string(), "1".to_string()),
        ("BUNDLE_GEMFILE".to_string(), gemfile.to_string()),
        ("BUNDLE_FROZEN".to_string(), "true".to_string()),
        ("BUNDLE_DISABLE_SHARED_GEMS".to_string(), "true".to_string()),
        ("BUNDLE_AUTO_INSTALL".to_string(), "false".to_string()),
        (
            "BUNDLE_DISABLE_VERSION_CHECK".to_string(),
            "true".to_string(),
        ),
    ]);
    env
}

/// Env for a lone script (`tog app.rb` with no Ruby project): the same
/// scrub as [`run_env`], with an empty `gem_home` in place of a gems
/// object, so the script sees the interpreter and its default gems only.
pub fn lone_env(gem_home: &Path) -> crate::tailors::EnvScrub {
    (
        ENV_REMOVE_PREFIXES.to_vec(),
        ENV_REMOVE.to_vec(),
        gem_env(gem_home),
    )
}

/// Env applied by `tog run` for a projected ruby environment. The user's
/// command may start in a subdirectory and still needs the root Gemfile,
/// so here it is named by its full path.
pub fn run_env(
    project_dir: &Path,
    gems_obj: &Path,
) -> (Vec<&'static str>, Vec<&'static str>, Vec<(String, String)>) {
    (
        ENV_REMOVE_PREFIXES.to_vec(),
        ENV_REMOVE.to_vec(),
        forced_env(&project_dir.join(GEMFILE).display().to_string(), gems_obj),
    )
}

/// The helper's `spec` mode over a `.gem` tog already verified: it reads
/// the embedded gemspec and needs no network, so it runs as a host-local
/// helper rather than through the door.
fn read_gem_spec(
    activity: &StoreActivity,
    ruby_obj: &Path,
    cwd: &Path,
    gem_home: &Path,
    args: &[&str],
) -> io::Result<std::process::Output> {
    let mut cmd = gem_spec_command(ruby_obj, cwd, gem_home, args);
    crate::kernel::supervise::local_output(&mut cmd, activity)
        .map_err(|e| io::Error::new(e.kind(), format!("run store ruby {args:?}: {e}")))
}

/// The command `read_gem_spec` starts: the forced environment, with `HOME`
/// in `cwd` so no user `.gemrc` or `.gem` directory is read.
fn gem_spec_command(
    ruby_obj: &Path,
    cwd: &Path,
    gem_home: &Path,
    args: &[&str],
) -> std::process::Command {
    let mut spec = ruby_tool_spec(ruby_obj, cwd, args, &forced_env(GEMFILE, gem_home));
    spec.env("HOME", cwd);
    spec.command()
}

/// The store Ruby tool `args[0]` with tog's forced environment, its output
/// captured.
fn ruby_tool_spec(
    ruby_obj: &Path,
    cwd: &Path,
    args: &[&str],
    environment: &[(String, String)],
) -> DelegateSpec {
    let mut spec = DelegateSpec::new(ruby_obj.join(format!("bin/{}", args[0])));
    spec.args(&args[1..]).lock_root(cwd);
    // Ruby FIRST on PATH: a gem executable named ruby/gem must never shadow.
    let path = format!(
        "{}:{}",
        ruby_obj.join("bin").display(),
        std::env::var("PATH").unwrap_or_default()
    );
    spec.env("PATH", path);
    spec.force_env(ENV_REMOVE_PREFIXES, ENV_REMOVE, environment);
    spec.capture();
    spec
}

/// Helper executed BY the pinned Ruby: parses the lock with Bundler's own
/// classes, validates the Gemfile/ruby directive, selects the local
/// platform's closure, and emits it dependency-first as JSON.
/// Extra modes install gems, check manifests, and read a downloaded .gem's
/// spec for post-download checks.
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
  gemfile, install_dir, native_libs = ARGV
  # tog's native library set, when given: mkmf takes the flags its
  # Makefile uses from extconf's arguments, never from the environment, and
  # each one replaces Ruby's own default, so the default leads.
  build_args = []
  if native_libs
    require "rbconfig"
    require "shellwords"
    include = Shellwords.escape(File.join(native_libs, "include"))
    lib = Shellwords.escape(File.join(native_libs, "lib"))
    build_args << "--with-cppflags=#{RbConfig::CONFIG["CPPFLAGS"]} -I#{include}"
    build_args << "--with-ldflags=#{RbConfig::CONFIG["LDFLAGS"]} -L#{lib} -Wl,-rpath,#{lib}"
  end
  installer = Gem::Installer.at(
    gemfile,
    install_dir: install_dir,
    bin_dir: File.join(install_dir, "bin"),
    ignore_dependencies: true,
    document: [],
    wrappers: true,
    env_shebang: true,
    build_args: build_args
  )
  installer.install
  puts "installed #{File.basename(gemfile)}"
  exit 0
end
if mode == "check"
  # Gemfile/lock equivalence + ruby-version gate. This mode EVALS THE
  # GEMFILE (arbitrary ruby, delegated resolver trust): its stdout is
  # never parsed by tog — only the exit status counts, so a hostile
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
         "executables" => spec.executables,
         "extensions" => spec.extensions }.to_json)
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
    /// The digest came from the rubygems.org API on this plan, so once the
    /// downloaded bytes match it, it is worth recording in the store.
    /// Planning state only: never serialized, so closures and object
    /// identities are unchanged by it.
    #[serde(skip)]
    pub digest_from_api: bool,
}

/// The store record kind holding rubygems.org's sha256 for one gem
/// coordinate.
const GEM_DIGESTS: &str = "rubygems-sha256";

/// A gem coordinate as a store record key: a JSON array, so no name,
/// version or platform spelling can run into the next field.
fn gem_digest_key(name: &str, version: &str, platform: &str) -> String {
    serde_json::json!([name, version, platform]).to_string()
}

/// The sha256 rubygems.org serves for this (name, version, platform), as an
/// earlier sync recorded it, or `None` when none has.
///
/// This is store data, not project data, which is why it may stand in for
/// the API where a plan cache in the project may not. A file in the project
/// ships with the repository, so a cache there says whatever the repo's
/// author wrote, and its predictable key makes it forgeable authority over
/// which bytes get installed. The store is written only by tog on this
/// machine, and a record exists only because tog asked rubygems.org for
/// exactly this coordinate's digest, downloaded
/// `rubygems.org/downloads/<full_name>.gem`, and found that the bytes hash
/// to that digest and their embedded gemspec names this coordinate.
/// rubygems.org never republishes a version, so the answer does not go
/// stale. A digest from a lock's CHECKSUMS section is never recorded: that
/// is the repository's claim, not rubygems.org's.
fn recorded_gem_digest(
    store: &Store,
    name: &str,
    version: &str,
    platform: &str,
) -> io::Result<Option<String>> {
    let value = store.read_record(GEM_DIGESTS, &gem_digest_key(name, version, platform))?;
    Ok(value
        .and_then(|value| value["sha256"].as_str().map(str::to_string))
        .filter(|hex| hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit())))
}

/// Record a digest the API gave for `gem` once its bytes have been checked
/// against it. A failed write costs the next sync one API call and nothing
/// else, so it is reported and the sync goes on.
fn record_gem_digest(store: &Store, activity: &StoreActivity, gem: &RubyGem) {
    let key = gem_digest_key(&gem.name, &gem.version, &gem.platform);
    let value = serde_json::json!({"sha256": gem.sha256});
    if let Err(error) = store.write_record(activity, GEM_DIGESTS, &key, &value) {
        ui::note(&format!(
            "{}: rubygems.org digest not recorded in the store ({error}); \
             the next sync asks rubygems.org again",
            gem.full_name
        ));
    }
}

/// Where a planned gem's `.gem` is fetched from. rubygems.org is the only
/// source the plan validator admits, so this is the single spelling of that
/// URL rather than a per-gem field.
fn gem_url(gem: &RubyGem) -> String {
    format!("https://rubygems.org/downloads/{}.gem", gem.full_name)
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

/// A gem's name, version, platform and full name, each one safe to place in
/// a URL path or query and in a store path.
fn valid_coordinates(name: &str, version: &str, platform: &str, full_name: &str) -> bool {
    valid_component(name)
        && valid_component(version)
        && (platform == "ruby" || valid_component(platform))
        && valid_component(full_name)
}

fn validate_plan(plan: &RubyPlan) -> io::Result<()> {
    let mut seen = std::collections::BTreeSet::new();
    for g in &plan.gems {
        if !valid_coordinates(&g.name, &g.version, &g.platform, &g.full_name) {
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

/// The project's Gemfile.lock text, read through the held descriptor so a
/// project directory renamed or replaced mid-sync cannot substitute another
/// project's lock. Absent reads as NotFound, as the path read reported it.
fn read_gemfile_lock(project: &ProjectRoot) -> io::Result<String> {
    project
        .read_input_string(Path::new("Gemfile.lock"))?
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "{}: not found",
                    project.path().join("Gemfile.lock").display()
                ),
            )
        })
}

/// The lock every plan reads, or the refusal that names it: `prepare`
/// generates it, and the command layer skips `prepare` under `--frozen`.
/// Checked before any toolchain is realized, so a frozen sync of an
/// unlocked project fails without a download.
pub fn require_lock(project: &ProjectRoot) -> io::Result<()> {
    if project.is_input_file(Path::new("Gemfile.lock")) {
        Ok(())
    } else {
        Err(crate::tailors::missing_lock(project, "Gemfile.lock"))
    }
}

/// Plan the gem closure: Bundler-delegated lock parsing + platform
/// selection, tog-pinned hashes (lock CHECKSUMS section when present, else
/// the digest an earlier sync verified and recorded in the store, else the
/// rubygems.org v2 API). The plan itself is never cached: every sync
/// re-derives it from the lock. The project is read through the held
/// descriptor; its path is only the store Ruby's working directory and
/// arguments.
pub fn plan_ruby(
    door: &mut ResolutionDoor<'_>,
    project: &ProjectRoot,
    ruby_obj: &Path,
    selected: &Selected,
) -> io::Result<(RubyPlan, String, crate::comforter::join::Digests)> {
    if !project.is_input_file(Path::new("Gemfile")) {
        return Err(err("Gemfile not found"));
    }
    require_lock(project)?;
    let lock = read_gemfile_lock(project)?;
    // No plan cache in the project: an editable cache with a predictable
    // key is forgeable authority. Planning re-derives from the lock every
    // sync; the store's digest records keep an unchanged lock off the
    // network, and its object cache makes realizes instant.

    // Both gates run confined with no route: full network denial.
    // Gate 1: Gemfile/lock equivalence + ruby directive. EVALS THE GEMFILE
    // (delegated resolver trust) — exit status only, stdout untrusted.
    let out = resolve::helper(door, project, ruby_obj, "check")?;
    if !out.status.success() {
        return Err(err(format!(
            "Gemfile/Gemfile.lock validation failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    // Gate 2: LOCK-ONLY closure derivation (never evaluates the Gemfile).
    let out = resolve::helper(door, project, ruby_obj, "plan")?;
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

    let store = door.store();
    let mut gems = Vec::new();
    for g in parsed.gems {
        // Checked before any of them is placed in a rubygems.org URL: a
        // lock entry such as `x?platform=java` would otherwise choose the
        // query the digest is asked with.
        if !valid_coordinates(&g.name, &g.version, &g.platform, &g.full_name) {
            return Err(err(format!(
                "invalid gem coordinates in Gemfile.lock: {} {} {}",
                g.name, g.version, g.platform
            )));
        }
        let mut digest_from_api = false;
        let recorded = match g.checksum {
            Some(_) => None,
            None => recorded_gem_digest(store, &g.name, &g.version, &g.platform)?,
        };
        let sha256 = match (g.checksum, recorded) {
            (Some(c), _) => c,
            (None, Some(recorded)) => recorded,
            (None, None) => {
                digest_from_api = true;
                // ALWAYS platform-qualified: the bare endpoint returns the
                // latest-PUSHED variant (racc 1.8.1 returns the java gem's
                // sha!). Validate the reply's platform too.
                let url = format!(
                    "https://rubygems.org/api/v2/rubygems/{}/versions/{}.json?platform={}",
                    g.name, g.version, g.platform
                );
                let body = crate::kernel::fetch::fetch_text(&url)
                    .map_err(|e| err(format!("{}: {e}", g.full_name)))?;
                digest_from_api_reply(&g.full_name, &g.version, &g.platform, &body)?
            }
        };
        gems.push(RubyGem {
            name: g.name,
            version: g.version,
            platform: g.platform,
            full_name: g.full_name,
            sha256,
            digest_from_api,
        });
    }
    let plan = RubyPlan {
        // The interpreter this plan was made under is the selected one, so
        // the plan records the selection's version, never the shipped pin.
        ruby_version: selected.version("ruby")?.to_string(),
        ruby_platform: parsed.ruby_platform,
        bundler_version: parsed.bundler,
        gems,
    };
    validate_plan(&plan)?;
    // Snapshot guard: the lock this plan derives from is the lock whose
    // digest provenance will record (Go precedent).
    let now = read_gemfile_lock(project)?;
    if now != lock {
        return Err(err("Gemfile.lock changed while planning; re-run 'tog'"));
    }
    // The resolution files this plan was built from, so the resolution
    // join binds a record to this generation of the Gemfile and its lock.
    let basis = resolve::resolution_basis(project)?;
    Ok((plan, hex::encode(Sha256::digest(lock.as_bytes())), basis))
}

/// The sha256 in one rubygems.org version reply, once the reply is shown to
/// describe the coordinate that was asked for. The bare endpoint answers
/// with whichever variant was pushed last, so a reply naming another
/// version or platform is refused rather than trusted for its digest.
fn digest_from_api_reply(
    full_name: &str,
    version: &str,
    platform: &str,
    body: &str,
) -> io::Result<String> {
    let v: serde_json::Value =
        serde_json::from_str(body).map_err(|e| err(format!("{full_name}: api json: {e}")))?;
    if v["number"].as_str() != Some(version) || v["platform"].as_str() != Some(platform) {
        return Err(err(format!(
            "{}: api returned {}-{} instead",
            full_name, v["number"], v["platform"]
        )));
    }
    Ok(v["sha"]
        .as_str()
        .ok_or_else(|| err(format!("{full_name}: api has no sha")))?
        .to_string())
}

/// Check that the gemspec the helper read out of a downloaded `.gem` names
/// exactly the planned coordinate, and that the plan's `full_name` is the
/// canonical spelling of that coordinate (the download URL is built from
/// it). Returns the gem's executables and whether it declares native
/// extensions.
fn spec_matches_plan(g: &RubyGem, spec_json: &[u8]) -> io::Result<(Vec<String>, bool)> {
    let spec: serde_json::Value = serde_json::from_slice(spec_json)
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
    let executables = spec["executables"]
        .as_array()
        .map(|exes| {
            exes.iter()
                .filter_map(|e| e.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    // A spec that does not say is treated as native: the hermetic build is
    // the safe side of the choice `install_gem` makes.
    let native = spec["extensions"]
        .as_array()
        .is_none_or(|extensions| !extensions.is_empty());
    Ok((executables, native))
}

/// Fetch one planned gem into the artifact cache, or find it there, verified
/// against the plan's sha256, then check that its embedded gemspec names
/// exactly the planned coordinate. Returns the cache lease, which keeps the
/// `.gem` from being swept while it is held, the gem's executables, and
/// whether its gemspec declares native extensions.
fn verify_gem(
    store: &Store,
    activity: &StoreActivity,
    ruby_obj: &Path,
    scratch: &Path,
    helper: &Path,
    g: &RubyGem,
) -> io::Result<(CacheLease, Vec<String>, bool)> {
    let url = gem_url(g);
    let lease = download_verified_held(store, activity, &url, &g.sha256)
        .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", g.full_name)))?;
    let out = read_gem_spec(
        activity,
        ruby_obj,
        scratch,
        scratch,
        &[
            "ruby",
            helper
                .to_str()
                .ok_or_else(|| err("helper path not UTF-8"))?,
            "spec",
            lease.to_str().ok_or_else(|| err("gem path not UTF-8"))?,
        ],
    )?;
    if !out.status.success() {
        return Err(err(format!(
            "{}: gemspec read failed: {}",
            g.full_name,
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    let (executables, native) = spec_matches_plan(g, &out.stdout)?;
    Ok((lease, executables, native))
}

/// On an object hit, record the API digests this plan used. The object
/// shows that some earlier build checked these gems, but a record is only
/// ever written on a check made now: each gem is verified again from the
/// artifact cache (or downloaded, when the cache was swept) before its
/// digest is recorded. Best effort, like every record write.
fn record_api_digests_on_hit(
    store: &Store,
    activity: &StoreActivity,
    plan: &RubyPlan,
    ruby_obj: &Path,
) {
    let pending: Vec<&RubyGem> = plan.gems.iter().filter(|g| g.digest_from_api).collect();
    if pending.is_empty() {
        return;
    }
    let result = (|| -> io::Result<()> {
        let scratch = store.stage_with_activity(activity)?;
        let helper = scratch.join("helper.rb");
        let outcome = fs::write(&helper, HELPER).map(|()| {
            for g in pending {
                match verify_gem(store, activity, ruby_obj, &scratch, &helper, g) {
                    Ok(_) => record_gem_digest(store, activity, g),
                    Err(error) => ui::note(&format!(
                        "{}: rubygems.org digest not recorded in the store ({error}); \
                         the next sync asks rubygems.org again",
                        g.full_name
                    )),
                }
            }
        });
        let _ = crate::kernel::store::remove_tree(&scratch);
        outcome
    })();
    if let Err(error) = result {
        ui::note(&format!(
            "rubygems.org digests not recorded in the store ({error}); \
             the next sync asks rubygems.org again"
        ));
    }
}

/// Realize the immutable GEM_HOME object: dependency-first sandboxed
/// installs (native extensions compile here, network denied).
pub fn realize_gems(
    store: &Store,
    activity: &StoreActivity,
    platform: Platform,
    plan: &RubyPlan,
    ruby_obj: &Path,
    selected: &Selected,
) -> io::Result<PathBuf> {
    crate::tailors::install_kinds();
    crate::kernel::platform::require_host(platform, "Ruby gems")?;
    let spec = ruby_spec(platform, selected)?;
    validate_plan(plan)?;
    // Fetch + post-download spec verification (all-or-nothing). It runs
    // before the cache lookup only when a gem's native classification is
    // not in the store yet: the identity names the native library set
    // exactly when the plan has a native gem (`native_libs`).
    let scratch = store.stage_with_activity(activity)?;
    let result = (|| {
        let helper = scratch.join("helper.rb");
        fs::write(&helper, HELPER)?;
        let mut verified = None;
        let has_native = match native_libs::persisted_classification(store, plan)? {
            Some(has_native) => has_native,
            None => {
                let gems = verify_plan(store, activity, ruby_obj, &scratch, &helper, plan)?;
                let has_native = gems.artifacts.iter().any(|(_, _, native)| *native);
                verified = Some(gems);
                has_native
            }
        };
        let mut native_libs_id = native_libs::identity_id(store, platform, has_native)?;
        let mut identity = ruby_gems_identity(&spec, plan, native_libs_id.as_deref());
        let cached = |identity: &Identity| -> io::Result<Option<PathBuf>> {
            let lookup_inputs = crate::kernel::hostview::host_build_inputs;
            match cached_gems_object(store, activity, identity, lookup_inputs)? {
                Some(id) => {
                    crate::kernel::policy::check_cached_with_activity(store, activity, &id)?;
                    Ok(Some(store.object_path(&id)))
                }
                None => Ok(None),
            }
        };
        if let Some(path) = cached(&identity)? {
            record_api_digests_on_hit(store, activity, plan, ruby_obj);
            return Ok(path);
        }
        let verified = match verified {
            Some(verified) => verified,
            None => {
                let verified = verify_plan(store, activity, ruby_obj, &scratch, &helper, plan)?;
                // The identity above came from the store's records; the
                // gemspecs just read are the authority. When they disagree,
                // the records were wrong (`verify_plan` has rewritten them),
                // and the object is built and named by the gemspecs.
                if let Some(fresh) = stale_native_classification(has_native, &verified) {
                    ui::note(&format!(
                        "the store recorded that this plan {} a native gem, but its gemspecs \
                         say it {}; the record is corrected and the gemspecs decide",
                        if has_native { "has" } else { "has no" },
                        if fresh { "has" } else { "has not" },
                    ));
                    native_libs_id = native_libs::identity_id(store, platform, fresh)?;
                    identity = ruby_gems_identity(&spec, plan, native_libs_id.as_deref());
                    // `verify_plan` recorded this plan's API digests already.
                    if let Some(path) = cached(&identity)? {
                        return Ok(path);
                    }
                }
                verified
            }
        };
        let native_libs = match native_libs_id {
            Some(_) => Some(crate::kernel::provider::nativelibs::ensure_native_libs(
                store, activity, platform,
            )?),
            None => None,
        };
        install_gems(
            store,
            activity,
            platform,
            plan,
            ruby_obj,
            &identity,
            &GemsWork {
                scratch: &scratch,
                helper: &helper,
                verified,
                native_libs: native_libs.as_ref(),
            },
        )
    })();
    let _ = crate::kernel::store::remove_tree(&scratch);
    result
}

/// The verified `.gem` of every planned gem, with whether its gemspec
/// declares native extensions, and the cache leases that keep them.
struct VerifiedGems<'p> {
    artifacts: Vec<(&'p RubyGem, PathBuf, bool)>,
    _leases: Vec<CacheLease>,
}

/// Whether `verified`'s gemspecs say the plan has a native gem, when that
/// differs from `recorded`, the answer the store's classification records
/// gave; `None` when they agree.
fn stale_native_classification(recorded: bool, verified: &VerifiedGems<'_>) -> Option<bool> {
    let fresh = verified.artifacts.iter().any(|(_, _, native)| *native);
    (fresh != recorded).then_some(fresh)
}

/// Download and verify every gem of `plan`, refusing two gems that provide
/// one executable, and record each gem's native classification.
fn verify_plan<'p>(
    store: &Store,
    activity: &StoreActivity,
    ruby_obj: &Path,
    scratch: &Path,
    helper: &Path,
    plan: &'p RubyPlan,
) -> io::Result<VerifiedGems<'p>> {
    let mut artifacts: Vec<(&RubyGem, PathBuf, bool)> = Vec::new();
    // One download per gem, and the lease from that download is held through
    // the sandboxed installs below, so no sweep can drop a `.gem` between
    // verification and use. That is all the lease closes: a same-user
    // replacement of a cache entry is still possible, so the install loop
    // digests every artifact again immediately before it copies it.
    let mut leases = Vec::new();
    let mut executables: BTreeMap<String, String> = BTreeMap::new();
    for g in &plan.gems {
        let (lease, exes, native) = verify_gem(store, activity, ruby_obj, scratch, helper, g)?;
        let file_path = lease.to_path_buf();
        leases.push(lease);
        // The bytes rubygems.org serves match the digest its API gave and
        // name this coordinate: that is what a digest record vouches for.
        if g.digest_from_api {
            record_gem_digest(store, activity, g);
        }
        native_libs::record_classification(store, activity, &g.sha256, native);
        for e in exes {
            if let Some(prev) = executables.insert(e.clone(), g.name.clone()) {
                return Err(err(format!(
                    "executable {e:?} provided by both {prev} and {}; refusing \
                     ambiguous bin dir",
                    g.name
                )));
            }
        }
        artifacts.push((g, file_path, native));
    }
    Ok(VerifiedGems {
        artifacts,
        _leases: leases,
    })
}

/// What the installs of one gems object work from: the scratch directory
/// and the helper in it, the verified gems, and the native library set
/// their native gems build with.
struct GemsWork<'a, 'p> {
    scratch: &'a Path,
    helper: &'a Path,
    verified: VerifiedGems<'p>,
    native_libs: Option<&'a crate::kernel::provider::nativelibs::NativeLibSet>,
}

/// Install every verified gem into a staged GEM_HOME, dependency-first, and
/// commit it under `identity` (or its host-fallback identity).
fn install_gems(
    store: &Store,
    activity: &StoreActivity,
    platform: Platform,
    plan: &RubyPlan,
    ruby_obj: &Path,
    identity: &Identity,
    work: &GemsWork,
) -> io::Result<PathBuf> {
    let (scratch, helper, artifacts) = (work.scratch, work.helper, &work.verified.artifacts);
    let staged = store.stage_with_activity(activity)?;
    let bin = staged.join("bin");
    fs::create_dir_all(&bin)?;
    let sandboxed = GemInstall {
        platform,
        activity,
        ruby_obj,
        helper,
        scratch,
        staged: &staged,
        native_libs: work.native_libs.map(|set| set.path.as_path()),
    };
    let mut fell_back = Vec::new();
    // The host state every fallback was built against (`same_host_state`).
    let mut host_inputs = None;
    for (g, file, native) in artifacts {
        // Re-verify immediately before use. The lease held since the download
        // stops a sweep, not a same-user replacement of the cache entry, so
        // the bytes about to be installed are digested again here.
        let hex = hash_file(file, Algo::Sha256)?;
        if hex != g.sha256 {
            return Err(err(format!(
                "{}: cached gem {} no longer matches the plan digest (expected {}, found {hex})",
                g.full_name,
                file.display(),
                g.sha256
            )));
        }
        // gem install only treats .gem-named arguments as local files (the
        // same lesson as pip and sdists); COPY from the cache, never link.
        let named = scratch.join(format!("{}.gem", g.full_name));
        fs::copy(file, &named)?;
        // Dependency-first order comes from the plan (helper topo-sort):
        // extconf.rb may require already-installed dependency gems.
        if let Some(built_against) = sandboxed.install(g, &named, *native)? {
            same_host_state(&mut host_inputs, &g.full_name, built_against)?;
            fell_back.push(g.full_name.clone());
        }
    }
    let mut deps = crate::kernel::store::ObjectDeps::new();
    deps.object_id(&crate::kernel::store::object_id_from_path(ruby_obj)?)?;
    if let Some(set) = work.native_libs {
        deps.object_id(&set.id)?;
    }
    for gem in &plan.gems {
        deps.cache_digest(Digest::sha256(&gem.sha256)?);
    }
    // A gem rebuilt against the whole host recorded `host-build-inputs`:
    // the object carries it, so a later cache hit replays it through
    // `check_cached_with_activity` above and a policy that denies the kind
    // refuses the cached object too. Such an object is committed under its
    // own identity, keyed by the host build inputs its fallbacks were built
    // against, and a record under the runtime-only id and those inputs
    // points a later sync on a host in the same state at it.
    let commit_identity = match &host_inputs {
        None => identity.clone(),
        Some(host_inputs) => ruby_gems_fallback_identity(identity, &fell_back, host_inputs),
    };
    let candidate = crate::kernel::policy::object_exceptions();
    let (object, applied) = store
        .commit_with_activity_and_deps(activity, &commit_identity, &staged, &candidate, &deps)
        .map_err(|e| io::Error::new(e.kind(), format!("commit gems: {e}")))?;
    if let Some(host_inputs) = &host_inputs {
        record_host_fallback(store, activity, identity, host_inputs, &fell_back);
    }
    for exception in applied {
        if !candidate.contains(&exception) {
            crate::kernel::policy::record(&exception.kind, &exception.subject, &exception.detail)?;
        }
    }
    Ok(object)
}

/// Project provenance (closure envelope); enforcement is env, set at run.
/// The closure writer still takes the project path: it publishes through
/// the descriptor the sync's toolchain guard holds and refuses a renamed
/// project before publication.
pub fn project_ruby_env(
    activity: &StoreActivity,
    project: &ProjectRoot,
    ruby_obj: &Path,
    gems_obj: &Path,
    plan: &RubyPlan,
    lock_sha256: &str,
    resolution_basis: &crate::comforter::join::Digests,
    selected: &Selected,
    ledgers: &[crate::kernel::resolve::ledger::LedgerObjects],
    attribution: &mut crate::kernel::policy::Attribution,
) -> io::Result<()> {
    let ruby_obj = ruby_obj.canonicalize()?;
    let gems_obj = gems_obj.canonicalize()?;
    let store = crate::comforter::store_from_object_path(&ruby_obj)
        .ok_or_else(|| err("Ruby object is not in a Tog store"))?;
    let mut refs = crate::comforter::ClosureRefs::new();
    refs.object_path(&store, activity, &ruby_obj)?;
    refs.object_path(&store, activity, &gems_obj)?;
    // Native extensions load the set's libraries at run time, through the
    // rpath they were linked with, so the project keeps it live too.
    let native_reference = crate::kernel::provider::nativelibs::env_reference(&gems_obj)?;
    if let Some(id) = native_reference.as_ref().and_then(|r| r["id"].as_str()) {
        refs.object_id(&store, activity, id)?;
    }
    // The planner doors' ledgers: evidence of what planning ran, kept as
    // long as this closure is, and named in the body so a root rebuilt
    // from the closure alone keeps them.
    let mut ledger_refs = Vec::new();
    for objects in ledgers {
        for id in [&objects.ledger, &objects.diagnostics] {
            refs.object_id(&store, activity, id)?;
            ledger_refs.push(crate::comforter::object_ref(&store.object_path(id))?);
        }
    }
    let mut body = closure_body(&ruby_obj, &gems_obj, plan, lock_sha256, selected)?;
    if let Some(reference) = native_reference {
        body["native_libs"] = reference;
    }
    body["resolution_ledgers"] = ledger_refs.into();
    body[crate::comforter::join::BASIS_FIELD] =
        crate::comforter::join::basis_value(resolution_basis);
    crate::comforter::write_closure(project, "ruby", body, &store, activity, refs, attribution)
}

/// The Ruby closure body: the projection's objects and plan, plus the
/// toolchain record that says which selection realized them. The
/// interpreter object is this ecosystem's runtime, and `project_ruby_env`
/// already holds it as a direct ref, so GC keeps it alive by the recorded
/// id.
fn closure_body(
    ruby_obj: &Path,
    gems_obj: &Path,
    plan: &RubyPlan,
    lock_sha256: &str,
    selected: &Selected,
) -> io::Result<serde_json::Value> {
    let mut body = serde_json::json!({
        "ruby_object": crate::comforter::object_ref(ruby_obj)?,
        "gems_object": crate::comforter::object_ref(gems_obj)?,
        "gemfile_lock_sha256": lock_sha256,
        "plan": plan,
    });
    let record = crate::comforter::toolchain::closure_record(selected, ruby_obj);
    crate::comforter::merge_record(&mut body, record);
    Ok(body)
}

/// A spec straight from the compiled pin table: the catalog's own rows, and
/// the fixture the identity goldens are written against.
#[cfg(test)]
fn pin_spec(platform: Platform) -> RubySpec {
    let pin = ruby_pin(platform).expect("pinned Ruby toolchain for test platform");
    RubySpec {
        platform: pin.platform,
        version: RUBY_VERSION.to_string(),
        provider: pin.provider.clone(),
        url: pin.url.to_string(),
        sha256: pin.digest.hex().to_string(),
    }
}

/// The shipped default Ruby, the object-id golden the identity tests hold:
/// adding a newer portable build to the catalog must not move it.
#[cfg(test)]
const RUBY_VERSION: &str = "3.4.6";

#[cfg(test)]
pub(crate) fn live_identity_cases(platform: Platform) -> Vec<Identity> {
    let spec = pin_spec(platform);
    let ruby = ruby_identity(&spec);
    let empty_plan = RubyPlan {
        ruby_version: RUBY_VERSION.into(),
        ruby_platform: if platform.is_macos() {
            "arm64-darwin20".into()
        } else {
            "x86_64-linux".into()
        },
        bundler_version: "2.6.9".into(),
        gems: Vec::new(),
    };
    let gem_plan = RubyPlan {
        gems: vec![RubyGem {
            name: "rake".into(),
            version: "13.2.1".into(),
            platform: "ruby".into(),
            full_name: "rake-13.2.1".into(),
            sha256: "a".repeat(64),
            digest_from_api: false,
        }],
        ..empty_plan.clone()
    };
    let gems = ruby_gems_identity(&spec, &gem_plan, None);
    let mut cases = vec![
        ruby,
        ruby_gems_identity(&spec, &empty_plan, None),
        gems.clone(),
    ];
    if !platform.is_macos() {
        let native_libs_id = format!("{}-libset-3", "c".repeat(40));
        cases.push(ruby_gems_identity(&spec, &gem_plan, Some(&native_libs_id)));
        cases.push(ruby_gems_fallback_identity(
            &gems,
            &["rake-13.2.1".into()],
            &"f".repeat(64),
        ));
    }
    cases
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
            crate::kernel::resolve::tripwire::RUBY_HELPER_SHA256
        );
    }

    /// The real `spec` call site passes the tripwire, and an interpreter
    /// option variable added to it is refused.
    #[test]
    fn the_gem_spec_read_passes_the_tripwire_only_as_built() {
        use crate::kernel::resolve::tripwire::refusal;
        use crate::kernel::testutil::{loosened, store_program};
        let store = TempDir::named("ruby-tripwire");
        let refused = |command: &Command| refusal(command, &store.0);
        store_program(&store.0, "objects/ruby/bin/ruby");
        let ruby = store.0.join("objects/ruby");
        let scratch = store.0.join("tmp/stage-scratch");
        fs::create_dir_all(&scratch).unwrap();
        let helper = scratch.join("helper.rb");
        fs::write(&helper, HELPER).unwrap();
        let gem = store.0.join("cache/sha256/x.gem");
        let spec_args = |gem: &Path| {
            [
                "ruby",
                helper.to_str().unwrap(),
                "spec",
                gem.to_str().unwrap(),
            ]
            .map(str::to_string)
        };
        let build_at = |ruby: &Path, gem: &Path| {
            let args = spec_args(gem);
            let args: Vec<&str> = args.iter().map(String::as_str).collect();
            gem_spec_command(ruby, &scratch, &scratch, &args)
        };
        let build = || build_at(&ruby, &gem);
        assert!(refused(&build()).is_none(), "{:?}", refused(&build()));
        for (key, value) in [
            ("RUBYOPT", "-r/tmp/evil"),
            ("RUBYLIB", "/tmp"),
            ("RUBYGEMS_GEMDEPS", "-"),
            ("BUNDLE_PATH", "/tmp"),
            ("GEM_PATH", "/tmp/gems"),
            ("GEM_HOME", "/tmp/gems"),
            ("GEMRC", "/home/someone/.gemrc"),
            ("HOME", "/home/someone"),
            ("PATH", "/home/someone/.rbenv/shims"),
        ] {
            let mut command = build();
            command.env(key, value);
            assert!(refused(&command).is_some(), "{key}");
        }
        // Another mode, or another script at the helper's path, each in
        // the environment as built.
        let (helper_arg, gem_arg) = (helper.to_str().unwrap(), gem.to_str().unwrap());
        for argv in [
            ["ruby", helper_arg, "check", gem_arg],
            ["ruby", helper_arg, "-rx", gem_arg],
        ] {
            let command = gem_spec_command(&ruby, &scratch, &scratch, &argv);
            assert!(refused(&command).is_some(), "{argv:?}");
        }
        fs::write(&helper, "puts 'not the helper'\n").unwrap();
        assert!(refused(&build()).is_some(), "an impostor helper.rb");
        fs::write(&helper, HELPER).unwrap();
        assert!(refused(&build()).is_none());
        let mut appended = build();
        appended.env("GEM_PATH", format!("{}:/tmp/gems", scratch.display()));
        assert!(refused(&appended).is_some(), "GEM_PATH with a second entry");
        let loosened_spec = loosened(build);
        let keys: Vec<&str> = loosened_spec.iter().map(|(key, _)| key.as_str()).collect();
        for key in [
            "GEM_HOME",
            "GEM_PATH",
            "GEMRC",
            "HOME",
            "PATH",
            "BUNDLE_GEMFILE",
        ] {
            assert!(keys.contains(&key), "{key} is not forced: {keys:?}");
        }
        for (key, command) in &loosened_spec {
            assert!(refused(command).is_some(), "loosened {key}");
        }
        assert!(
            refused(&build_at(&ruby, Path::new("/tmp/x.gem"))).is_some(),
            "a .gem outside the store"
        );
        let host = TempDir::named("ruby-tripwire-host");
        store_program(&host.0, "ruby/bin/ruby");
        assert!(
            refused(&build_at(&host.0.join("ruby"), &gem)).is_some(),
            "a ruby outside the store"
        );
    }
    use super::*;
    use crate::kernel::testutil::TempDir;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::process::Command;

    #[test]
    fn ruby_pins_cover_supported_platforms() {
        let catalog = toolchain_catalog().unwrap();
        assert!(
            catalog.bundles().len() > 1,
            "the catalog holds more than the default"
        );
        for bundle in catalog.bundles() {
            for platform in Platform::ALL {
                let row = bundle.artifact(*platform, "ruby").unwrap();
                assert!(
                    row.url.starts_with(&format!(
                        "https://github.com/Homebrew/homebrew-portable-ruby/releases/download/{}/portable-ruby-{}.",
                        row.build, row.build
                    )),
                    "{}",
                    row.url
                );
            }
        }
        // The default is unchanged by the newer rows around it.
        for platform in Platform::ALL {
            assert_eq!(ruby_pin(*platform).unwrap().platform, *platform);
            assert_eq!(ruby_pin(*platform).unwrap().build, RUBY_VERSION);
        }
        assert_eq!(
            shipped_selection().unwrap().version("ruby").unwrap(),
            RUBY_VERSION
        );
        let linux = ruby_pin(Platform::X86_64UnknownLinuxGnu).unwrap();
        assert_eq!(linux.url, "https://github.com/Homebrew/homebrew-portable-ruby/releases/download/3.4.6/portable-ruby-3.4.6.x86_64_linux.bottle.tar.gz");
        assert_eq!(
            linux.digest.hex(),
            "40932a3950ccc8bf9d13d98e692e5518427cc66b4f9520956cec349629d25259"
        );
    }

    pub(super) fn linux_test_plan() -> RubyPlan {
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
                digest_from_api: false,
            }],
        }
    }

    /// A classification record that disagrees with the gemspecs read on a
    /// cache miss is caught, and the identity is decided by the gemspecs:
    /// a gem recorded as pure Ruby that is native names the set.
    #[test]
    fn a_stale_native_record_is_overruled_by_the_gemspecs() {
        let plan = linux_test_plan();
        let spec = pin_spec(Platform::X86_64UnknownLinuxGnu);
        let verified = |native: bool| VerifiedGems {
            artifacts: vec![(&plan.gems[0], PathBuf::from("/cache/rake.gem"), native)],
            _leases: Vec::new(),
        };
        assert_eq!(stale_native_classification(false, &verified(false)), None);
        assert_eq!(stale_native_classification(true, &verified(true)), None);
        assert_eq!(
            stale_native_classification(false, &verified(true)),
            Some(true)
        );
        assert_eq!(
            stale_native_classification(true, &verified(false)),
            Some(false)
        );

        let set = format!("{}-libset-3", "c".repeat(40));
        let recorded = ruby_gems_identity(&spec, &plan, None);
        let corrected = ruby_gems_identity(&spec, &plan, Some(&set));
        assert_eq!(recorded.inputs["native"], native_libs::NATIVE_NONE);
        assert_eq!(corrected.inputs["native"], native_libs::NATIVE_LIBS_MOUNTED);
        assert_ne!(recorded.object_id(), corrected.object_id());
    }

    #[test]
    fn linux_and_darwin_identities_are_distinct_rows_of_one_schema() {
        let darwin_pin = pin_spec(Platform::Aarch64AppleDarwin);
        let linux_pin = pin_spec(Platform::X86_64UnknownLinuxGnu);
        let darwin = ruby_identity(&darwin_pin);
        let linux = ruby_identity(&linux_pin);
        assert_ne!(darwin.object_id(), linux.object_id());
        // Same input keys: the Linux pin is a row, not a second recipe.
        assert_eq!(
            darwin.inputs.keys().collect::<Vec<_>>(),
            linux.inputs.keys().collect::<Vec<_>>()
        );
        assert_eq!(linux.inputs["platform"], "x86_64-unknown-linux-gnu");
        assert_eq!(linux.inputs["artifact_sha256"], linux_pin.sha256);

        let plan = linux_test_plan();
        let darwin_gems = ruby_gems_identity(&darwin_pin, &plan, None);
        let linux_gems = ruby_gems_identity(&linux_pin, &plan, None);
        assert_ne!(darwin_gems.object_id(), linux_gems.object_id());
        assert!(linux_gems.inputs["installer"].contains(&linux_pin.sha256));
    }

    #[test]
    fn linux_identities_pinned() {
        // Goldens for the shared-store check: a Mac
        // and a Linux box realizing the same pin must not collide, and the
        // Linux ids must not drift without a deliberate identity change.
        let spec = pin_spec(Platform::X86_64UnknownLinuxGnu);
        assert_eq!(
            (
                ruby_identity(&spec).object_id(),
                ruby_gems_identity(&spec, &linux_test_plan(), None).object_id(),
            ),
            (
                "192a4c7b501dd09eb3c76a3ebd427e8077fbda6e-ruby-3.4.6".to_string(),
                // runtime-only/2: native extensions see the C runtime alone;
                // native none: the plan names no native library set.
                "b20b2d01edb86ced8eb3b8d0a56c07a51a07a2d6-gems-1".to_string(),
            )
        );
    }

    /// Linux gem objects name the host view their extensions built
    /// against; Darwin's inputs are what they were, so its ids stand.
    #[test]
    fn linux_gem_identity_names_the_runtime_only_view() {
        let plan = linux_test_plan();
        let linux = ruby_gems_identity(&pin_spec(Platform::X86_64UnknownLinuxGnu), &plan, None);
        assert_eq!(linux.inputs["build_view"], "runtime-only/2");
        let darwin = ruby_gems_identity(&pin_spec(Platform::Aarch64AppleDarwin), &plan, None);
        assert!(!darwin.inputs.contains_key("build_view"), "{darwin:?}");
    }

    /// A Linux gems identity spells out its native decision, names the
    /// native library set exactly when it says so, and a macOS one names
    /// neither (#329).
    #[test]
    fn the_native_decision_and_the_library_set_agree() {
        let plan = linux_test_plan();
        let linux = pin_spec(Platform::X86_64UnknownLinuxGnu);
        let set = format!("{}-libset-3", "c".repeat(40));
        let none = ruby_gems_identity(&linux, &plan, None);
        let mounted = ruby_gems_identity(&linux, &plan, Some(&set));
        assert_eq!(none.inputs["native"], native_libs::NATIVE_NONE);
        assert_eq!(mounted.inputs["native"], native_libs::NATIVE_LIBS_MOUNTED);
        assert_eq!(mounted.inputs["native_libs"], set);
        assert_ne!(none.object_id(), mounted.object_id());
        let grammar = crate::kernel::objmeta::check_identity_grammar;
        assert_eq!(grammar(&none), Ok(()));
        assert_eq!(grammar(&mounted), Ok(()));
        let mut dropped = mounted.clone();
        dropped.inputs.remove("native_libs");
        assert!(grammar(&dropped).unwrap_err().contains("native decision"));
        let mut no_decision = none.clone();
        no_decision.inputs.remove("native");
        assert!(grammar(&no_decision).is_err());
        let mut empty = mounted.clone();
        empty.inputs.retain(|key, _| !key.starts_with("gem:"));
        empty.version = "0".into();
        assert!(grammar(&empty).unwrap_err().contains("requires a gem:"));
        let darwin_spec = pin_spec(Platform::Aarch64AppleDarwin);
        let darwin = ruby_gems_identity(&darwin_spec, &plan, Some(&set));
        assert!(!darwin.inputs.contains_key("native"), "{darwin:?}");
        assert!(!darwin.inputs.contains_key("native_libs"), "{darwin:?}");
        let mut foreign = darwin.clone();
        foreign
            .inputs
            .insert("native".into(), native_libs::NATIVE_NONE.into());
        assert!(grammar(&foreign).unwrap_err().contains("Linux-only"));
    }

    /// Native classifications kept in the store answer for a plan only
    /// when every gem has one.
    #[test]
    fn a_plan_is_classified_only_when_every_gem_is() {
        let temp = TempDir::named("ruby-native-records");
        let root = temp.0.join("store");
        for sub in ["objects", "meta", "tmp"] {
            fs::create_dir_all(root.join(sub)).unwrap();
        }
        let store = Store::for_test(root.canonicalize().unwrap());
        let activity = store
            .activity(crate::kernel::activity::ActivityMode::Shared)
            .unwrap();
        let mut plan = linux_test_plan();
        let mut second = plan.gems[0].clone();
        second.sha256 = "b".repeat(64);
        plan.gems.push(second);
        let persisted =
            |plan: &RubyPlan| native_libs::persisted_classification(&store, plan).unwrap();
        assert_eq!(persisted(&plan), None);
        native_libs::record_classification(&store, &activity, &plan.gems[0].sha256, false);
        assert_eq!(persisted(&plan), None);
        native_libs::record_classification(&store, &activity, &plan.gems[1].sha256, true);
        assert_eq!(persisted(&plan), Some(true));
        assert_eq!(
            native_libs::identity_id(&store, Platform::Aarch64AppleDarwin, true).unwrap(),
            None
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
        fs::write(
            tree.join("include/ruby-3.4.0/ruby.h"),
            b"#define RUBY_H 1\n",
        )
        .unwrap();
        fs::set_permissions(tree.join("bin/ruby"), fs::Permissions::from_mode(0o755)).unwrap();

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
        extract_ruby_bottle_for_test(&archive, &staged).unwrap();
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
        let identity = ruby_identity(&pin_spec(platform));
        assert_eq!(
            identity.object_id(),
            "c4c2411b7540521f48dcdd8cff25786e261ed1ee-ruby-3.4.6"
        );
    }

    #[test]
    fn darwin_ruby_gems_identity_unchanged() {
        let spec = pin_spec(Platform::Aarch64AppleDarwin);
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
                digest_from_api: false,
            }],
        };
        let identity = ruby_gems_identity(&spec, &plan, None);
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
            digest_from_api: false,
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
                    digest_from_api: false,
                },
                RubyGem {
                    name: "nokogiri".into(),
                    version: "1.18.10".into(),
                    platform: "x86_64-linux".into(),
                    full_name: "nokogiri-1.18.10-x86_64-linux".into(),
                    sha256: "b".repeat(64),
                    digest_from_api: false,
                },
            ],
        };
        assert!(validate_plan(&plan).is_ok());
    }

    /// The selection is the only authority on the sync path, so the object
    /// it realizes must have the id the pin table realized before selection
    /// existed, on both platforms: that is the id every cached Ruby already
    /// has. If this drifts, every cached Ruby is orphaned.
    #[test]
    fn a_selected_row_and_the_pin_build_the_same_identity() {
        let selected = shipped_selection().unwrap();
        for platform in Platform::ALL {
            let from_lock = ruby_spec(*platform, &selected).unwrap();
            let from_pin = pin_spec(*platform);
            assert_eq!(from_lock.version, from_pin.version);
            assert_eq!(from_lock.url, from_pin.url);
            assert_eq!(from_lock.sha256, from_pin.sha256);
            assert_eq!(
                ruby_identity(&from_lock).object_id(),
                ruby_identity(&from_pin).object_id(),
                "{}",
                platform.triple()
            );
            let plan = linux_test_plan();
            assert_eq!(
                ruby_gems_identity(&from_lock, &plan, None).object_id(),
                ruby_gems_identity(&from_pin, &plan, None).object_id()
            );
        }
    }

    #[test]
    fn an_unknown_recipe_and_a_foreign_selection_are_both_refused() {
        let mut selected = shipped_selection().unwrap();
        for row in &mut selected.bundle.artifacts {
            row.recipe = "ruby-toolchain/99".into();
        }
        let error = ruby_spec(Platform::X86_64UnknownLinuxGnu, &selected)
            .unwrap_err()
            .to_string();
        assert!(error.contains("ruby-toolchain/99"), "{error}");
        assert!(error.contains("upgrade tog"), "{error}");

        let mut foreign = shipped_selection().unwrap();
        foreign.ecosystem = "python".into();
        let error = ruby_spec(Platform::X86_64UnknownLinuxGnu, &foreign)
            .unwrap_err()
            .to_string();
        assert!(error.contains("not ruby"), "{error}");

        // A selection of the right ecosystem with no row for this host is a
        // refusal too, and it names what it could not find.
        let mut empty = shipped_selection().unwrap();
        empty.bundle.artifacts.clear();
        let error = ruby_spec(Platform::X86_64UnknownLinuxGnu, &empty)
            .unwrap_err()
            .to_string();
        assert!(error.contains("x86_64-unknown-linux-gnu"), "{error}");
    }

    /// Every closure this tailor writes carries which bundle realized it and
    /// which store object that bundle became: `tog status` compares the one,
    /// `tog run` resolves the other.
    #[test]
    fn the_closure_body_records_the_bundle_and_the_runtime_object() {
        let selected = shipped_selection().unwrap();
        let ruby_obj = Path::new("/store/objects/abc-ruby-3.4.6");
        let body = closure_body(
            ruby_obj,
            Path::new("/store/objects/def-gems-1"),
            &linux_test_plan(),
            &"c".repeat(64),
            &selected,
        )
        .unwrap();
        assert_eq!(body["toolchain"]["ecosystem"], "ruby");
        assert_eq!(body["toolchain"]["bundle_id"], selected.bundle_id());
        assert_eq!(body["toolchain"]["versions"]["ruby"], RUBY_VERSION);
        assert_eq!(body["runtime_object"]["id"], "abc-ruby-3.4.6");
        assert_eq!(
            body["runtime_object"]["path"],
            ruby_obj.display().to_string()
        );
        // The runtime object is the interpreter the projection already
        // records, and every pre-existing key survives beside the record.
        assert_eq!(body["ruby_object"]["id"], body["runtime_object"]["id"]);
        assert_eq!(body["gems_object"]["id"], "def-gems-1");
        assert_eq!(body["gemfile_lock_sha256"], "c".repeat(64));
        assert_eq!(body["plan"]["ruby_platform"], "x86_64-linux");
    }

    /// The durable root/2 record `project_ruby_env` publishes names exactly
    /// the Ruby interpreter object and the gems object it was handed:
    /// nothing inferred from the closure JSON, nothing missing.
    #[test]
    fn closure_refs_name_every_object_this_producer_created() {
        let _store_env = crate::kernel::store::STORE_ENV_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let _attribution_lock = crate::kernel::policy::attribution_test_lock();
        let mut attribution = crate::kernel::policy::Attribution::open("ruby").unwrap();
        let temp = TempDir::new();
        let store_root = temp.0.join("store");
        for sub in ["objects", "meta", "cache/sha256", "tmp", "roots"] {
            fs::create_dir_all(store_root.join(sub)).unwrap();
        }
        let store = Store::for_test(store_root.canonicalize().unwrap());
        let lease = store
            .activity(crate::kernel::activity::ActivityMode::Shared)
            .unwrap();
        let activity = &lease;
        let ruby_id = store.publish_bare_test("ruby", RUBY_VERSION);
        let gems_id = store.publish_bare_test("gems", "1");
        let project = temp.0.join("project");
        fs::create_dir_all(&project).unwrap();
        project_ruby_env(
            activity,
            &ProjectRoot::open(&project).unwrap(),
            &store.object_path(&ruby_id),
            &store.object_path(&gems_id),
            &linux_test_plan(),
            &"c".repeat(64),
            &Default::default(),
            &shipped_selection().unwrap(),
            &[],
            &mut attribution,
        )
        .unwrap();
        attribution.finish(true).unwrap();

        let roots = store.roots().unwrap();
        assert_eq!(roots.len(), 1, "no durable root record was published");
        let record = roots[0].record.as_ref().expect("root/2 record");
        assert_eq!(
            record.objects,
            std::collections::BTreeSet::from([ruby_id, gems_id])
        );
        assert!(record.projections.is_empty(), "{:?}", record.projections);

        // `gc --register` rebuilds the same record from this closure alone.
        drop(lease);
        let reimported = crate::kernel::store::reimport_root_for_test(&store, &project).unwrap();
        assert_eq!(reimported.objects, record.objects);
        assert_eq!(reimported.projections, record.projections);
    }

    /// A project renamed mid-sync with another project put at its old path:
    /// detection and the lock reader keep reading the directory the sync
    /// opened, never the replacement.
    #[test]
    fn a_held_root_keeps_reading_the_original_project_after_a_rename() {
        use crate::tailors::Tailor as _;
        let temp = TempDir::new();
        let project = temp.0.join("project");
        fs::create_dir_all(&project).unwrap();
        fs::write(project.join("Gemfile"), "source \"https://rubygems.org\"\n").unwrap();
        fs::write(project.join("Gemfile.lock"), "ORIGINAL\n").unwrap();
        let root = ProjectRoot::open(&project).unwrap();

        fs::rename(&project, temp.0.join("moved")).unwrap();
        fs::create_dir_all(&project).unwrap();
        fs::write(project.join("Gemfile.lock"), "REPLACEMENT\n").unwrap();

        assert!(tailor::Ruby.detect(&root).unwrap());
        assert_eq!(read_gemfile_lock(&root).unwrap(), "ORIGINAL\n");
        let fresh = ProjectRoot::open(&project).unwrap();
        assert!(!tailor::Ruby.detect(&fresh).unwrap());
        assert_eq!(read_gemfile_lock(&fresh).unwrap(), "REPLACEMENT\n");
    }

    /// A recorded digest is found only by its exact (name, version,
    /// platform), and a record that is not a sha256 is no record.
    #[test]
    fn gem_digest_records_are_keyed_by_the_whole_coordinate() {
        let temp = TempDir::named("ruby-gem-digests");
        let root = temp.0.join("store");
        for sub in ["objects", "meta", "tmp"] {
            fs::create_dir_all(root.join(sub)).unwrap();
        }
        let store = Store::for_test(root.canonicalize().unwrap());
        let activity = store
            .activity(crate::kernel::activity::ActivityMode::Shared)
            .unwrap();
        let gem = RubyGem {
            name: "racc".into(),
            version: "1.8.1".into(),
            platform: "ruby".into(),
            full_name: "racc-1.8.1".into(),
            sha256: "c".repeat(64),
            digest_from_api: true,
        };
        assert_eq!(
            recorded_gem_digest(&store, "racc", "1.8.1", "ruby").unwrap(),
            None
        );
        record_gem_digest(&store, &activity, &gem);
        assert_eq!(
            recorded_gem_digest(&store, "racc", "1.8.1", "ruby").unwrap(),
            Some("c".repeat(64))
        );
        assert_eq!(
            recorded_gem_digest(&store, "racc", "1.8.1", "java").unwrap(),
            None
        );
        assert_eq!(
            recorded_gem_digest(&store, "racc", "1.8.2", "ruby").unwrap(),
            None
        );
        // Name and version never run together: "a-1" at "2" is not "a" at
        // "1-2".
        let key = gem_digest_key("a-1", "2", "ruby");
        assert_ne!(key, gem_digest_key("a", "1-2", "ruby"));
        store
            .write_record(
                &activity,
                GEM_DIGESTS,
                &key,
                &serde_json::json!({"sha256": "zz"}),
            )
            .unwrap();
        assert_eq!(
            recorded_gem_digest(&store, "a-1", "2", "ruby").unwrap(),
            None
        );
        // The digest is planning state: it never reaches a serialized plan.
        let json = serde_json::to_value(&gem).unwrap();
        assert!(json.get("digest_from_api").is_none(), "{json}");
    }

    /// tog's own Bundler runs start inside the held project directory and
    /// name the Gemfile relative to it (#499). `tog run` may start in a
    /// subdirectory, so it keeps the root Gemfile's full path.
    #[test]
    fn delegates_name_the_gemfile_relative_to_the_held_project() {
        let gemfile = |env: &[(String, String)]| {
            env.iter()
                .find(|(key, _)| key == "BUNDLE_GEMFILE")
                .map(|(_, value)| value.clone())
        };
        let spec = ruby_tool_spec(
            Path::new("/ruby"),
            Path::new("/p"),
            &["bundle", "lock"],
            &forced_env(GEMFILE, Path::new("/g")),
        );
        assert!(format!("{:?}", spec.command()).contains("BUNDLE_GEMFILE=\"Gemfile\""));
        assert_eq!(
            gemfile(&forced_env(GEMFILE, Path::new("/g"))).as_deref(),
            Some("Gemfile")
        );
        let (_, _, run) = run_env(Path::new("/p"), Path::new("/g"));
        assert_eq!(gemfile(&run).as_deref(), Some("/p/Gemfile"));
    }

    #[test]
    fn forced_env_covers_bundler_side_doors() {
        let env = forced_env(GEMFILE, Path::new("/g"));
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
        // The host-local tripwire checks the spec read against its own copy
        // of the forced list.
        let env = forced_env(GEMFILE, Path::new("/g"));
        let mut keys: Vec<&str> = env.iter().map(|(key, _)| key.as_str()).collect();
        let mut checked = crate::kernel::resolve::tripwire::RUBY_FORCED.to_vec();
        keys.sort_unstable();
        checked.sort_unstable();
        assert_eq!(keys, checked);
    }
}

/// Offline tests for the two rubygems.org checks (#348): the version reply
/// that supplies a digest, and the embedded gemspec that must name the
/// planned coordinate before a downloaded `.gem` is installed.
#[cfg(test)]
mod rubygems_check_tests {
    use super::*;

    const SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const OTHER_SHA: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    /// A rubygems.org version reply for one coordinate, with the fields
    /// tog reads and the ones it ignores, all consistent with each other.
    fn api_reply(name: &str, number: &str, platform: &str, sha: &str) -> String {
        let full_name = if platform == "ruby" {
            format!("{name}-{number}")
        } else {
            format!("{name}-{number}-{platform}")
        };
        serde_json::json!({
            "name": name, "number": number, "platform": platform, "sha": sha,
            "gem_uri": format!("https://rubygems.org/gems/{full_name}.gem"),
        })
        .to_string()
    }

    #[test]
    fn an_api_reply_for_another_version_is_refused() {
        let body = api_reply("racc", "1.8.0", "ruby", SHA);
        let error = digest_from_api_reply("racc-1.8.1", "1.8.1", "ruby", &body)
            .unwrap_err()
            .to_string();
        assert_eq!(error, "racc-1.8.1: api returned \"1.8.0\"-\"ruby\" instead");
    }

    #[test]
    fn an_api_reply_for_another_platform_is_refused() {
        // The racc 1.8.1 case that motivated the platform query: the bare
        // endpoint answers with the java gem, whose sha is not the ruby one.
        let body = api_reply("racc", "1.8.1", "java", SHA);
        let error = digest_from_api_reply("racc-1.8.1", "1.8.1", "ruby", &body)
            .unwrap_err()
            .to_string();
        assert_eq!(error, "racc-1.8.1: api returned \"1.8.1\"-\"java\" instead");
    }

    #[test]
    fn an_api_reply_with_no_version_or_platform_field_is_refused() {
        // One field at a time: the other is correct, so only the missing or
        // mistyped one can be what refuses the reply.
        for (body, shown) in [
            (r#"{"platform": "ruby", "sha": "aa"}"#, "null-\"ruby\""),
            (
                r#"{"number": null, "platform": "ruby", "sha": "aa"}"#,
                "null-\"ruby\"",
            ),
            (
                r#"{"number": 1.81, "platform": "ruby", "sha": "aa"}"#,
                "1.81-\"ruby\"",
            ),
            (r#"{"number": "1.8.1", "sha": "aa"}"#, "\"1.8.1\"-null"),
            (
                r#"{"number": "1.8.1", "platform": null, "sha": "aa"}"#,
                "\"1.8.1\"-null",
            ),
            (
                r#"{"number": "1.8.1", "platform": ["ruby"], "sha": "aa"}"#,
                "\"1.8.1\"-[\"ruby\"]",
            ),
            (r#"[]"#, "null-null"),
        ] {
            let error = digest_from_api_reply("racc-1.8.1", "1.8.1", "ruby", body)
                .unwrap_err()
                .to_string();
            assert_eq!(
                error,
                format!("racc-1.8.1: api returned {shown} instead"),
                "{body}"
            );
        }
    }

    #[test]
    fn an_api_reply_without_a_string_sha_is_refused() {
        for sha in ["null", "123", "[]", "{}"] {
            let body = format!(r#"{{"number": "1.8.1", "platform": "ruby", "sha": {sha}}}"#);
            let error = digest_from_api_reply("racc-1.8.1", "1.8.1", "ruby", &body)
                .unwrap_err()
                .to_string();
            assert_eq!(error, "racc-1.8.1: api has no sha", "{sha}");
        }
        let body = r#"{"number": "1.8.1", "platform": "ruby"}"#;
        let error = digest_from_api_reply("racc-1.8.1", "1.8.1", "ruby", body)
            .unwrap_err()
            .to_string();
        assert_eq!(error, "racc-1.8.1: api has no sha");
    }

    #[test]
    fn an_api_reply_that_is_not_json_is_refused() {
        let error = digest_from_api_reply("racc-1.8.1", "1.8.1", "ruby", "<html>")
            .unwrap_err()
            .to_string();
        let serde = serde_json::from_str::<serde_json::Value>("<html>").unwrap_err();
        assert_eq!(error, format!("racc-1.8.1: api json: {serde}"));
    }

    #[test]
    fn control_a_matching_api_reply_yields_its_sha() {
        // Two replies with different digests: the value must come from the
        // reply, not from anywhere else.
        let body = api_reply("racc", "1.8.1", "ruby", SHA);
        let sha = digest_from_api_reply("racc-1.8.1", "1.8.1", "ruby", &body).unwrap();
        assert_eq!(sha, SHA);
        // A platform-qualified coordinate matches its own variant.
        let body = api_reply("nokogiri", "1.18.10", "x86_64-linux", OTHER_SHA);
        let sha = digest_from_api_reply(
            "nokogiri-1.18.10-x86_64-linux",
            "1.18.10",
            "x86_64-linux",
            &body,
        )
        .unwrap();
        assert_eq!(sha, OTHER_SHA);
    }

    fn gem(name: &str, version: &str, platform: &str, full_name: &str) -> RubyGem {
        RubyGem {
            name: name.into(),
            version: version.into(),
            platform: platform.into(),
            full_name: full_name.into(),
            sha256: SHA.into(),
            digest_from_api: false,
        }
    }

    fn spec(name: &str, version: &str, platform: &str) -> Vec<u8> {
        serde_json::json!({
            "name": name, "version": version, "platform": platform,
            "executables": ["rake"], "extensions": [],
        })
        .to_string()
        .into_bytes()
    }

    #[test]
    fn a_gemspec_naming_another_gem_version_or_platform_is_refused() {
        let planned = gem("rake", "13.2.1", "ruby", "rake-13.2.1");
        for (name, version, platform, shown) in [
            ("rack", "13.2.1", "ruby", "\"rack\" \"13.2.1\" \"ruby\""),
            ("rake", "13.2.0", "ruby", "\"rake\" \"13.2.0\" \"ruby\""),
            ("rake", "13.2.1", "java", "\"rake\" \"13.2.1\" \"java\""),
            ("Rake", "13.2.1", "ruby", "\"Rake\" \"13.2.1\" \"ruby\""),
        ] {
            let error = spec_matches_plan(&planned, &spec(name, version, platform))
                .unwrap_err()
                .to_string();
            assert_eq!(
                error,
                format!("rake-13.2.1: embedded gemspec disagrees with the plan ({shown})"),
            );
        }
        // A field missing from the spec reads as null and disagrees too,
        // one at a time with the other two correct.
        for (body, shown) in [
            (
                r#"{"version": "13.2.1", "platform": "ruby"}"#,
                "null \"13.2.1\" \"ruby\"",
            ),
            (
                r#"{"name": "rake", "platform": "ruby"}"#,
                "\"rake\" null \"ruby\"",
            ),
            (
                r#"{"name": "rake", "version": "13.2.1"}"#,
                "\"rake\" \"13.2.1\" null",
            ),
        ] {
            let error = spec_matches_plan(&planned, body.as_bytes())
                .unwrap_err()
                .to_string();
            assert_eq!(
                error,
                format!("rake-13.2.1: embedded gemspec disagrees with the plan ({shown})"),
                "{body}"
            );
        }
    }

    #[test]
    fn a_plan_full_name_that_is_not_the_canonical_spelling_is_refused() {
        // The gemspec agrees with name/version/platform, but the download
        // URL is built from full_name, so it must be the canonical spelling.
        for (platform, full_name) in [
            ("ruby", "rake-13.2.1-ruby"),
            ("ruby", "rake-13.2.0"),
            ("ruby", "rack-13.2.1"),
            ("x86_64-linux", "rake-13.2.1"),
            ("x86_64-linux", "rake-13.2.1-java"),
        ] {
            let planned = gem("rake", "13.2.1", platform, full_name);
            let error = spec_matches_plan(&planned, &spec("rake", "13.2.1", platform))
                .unwrap_err()
                .to_string();
            assert_eq!(
                error,
                format!(
                    "{full_name}: embedded gemspec disagrees with the plan \
                     (\"rake\" \"13.2.1\" \"{platform}\")"
                ),
                "{full_name}"
            );
        }
    }

    #[test]
    fn a_gemspec_that_is_not_json_is_refused() {
        let planned = gem("rake", "13.2.1", "ruby", "rake-13.2.1");
        let error = spec_matches_plan(&planned, b"not json")
            .unwrap_err()
            .to_string();
        let serde = serde_json::from_slice::<serde_json::Value>(b"not json").unwrap_err();
        assert_eq!(error, format!("rake-13.2.1: spec json: {serde}"));
    }

    #[test]
    fn control_a_matching_gemspec_yields_executables_and_the_native_flag() {
        let planned = gem("rake", "13.2.1", "ruby", "rake-13.2.1");
        let (executables, native) =
            spec_matches_plan(&planned, &spec("rake", "13.2.1", "ruby")).unwrap();
        assert_eq!(executables, ["rake"]);
        assert!(!native, "an empty extensions list is pure ruby");

        let qualified = gem(
            "nokogiri",
            "1.18.10",
            "x86_64-linux",
            "nokogiri-1.18.10-x86_64-linux",
        );
        let body = serde_json::json!({
            "name": "nokogiri", "version": "1.18.10", "platform": "x86_64-linux",
            "executables": ["nokogiri", 7], "extensions": ["ext/nokogiri/extconf.rb"],
        })
        .to_string();
        let (executables, native) = spec_matches_plan(&qualified, body.as_bytes()).unwrap();
        assert_eq!(
            executables,
            ["nokogiri"],
            "a non-string executable is dropped"
        );
        assert!(native);

        // A spec that does not list extensions at all is treated as native.
        let body = br#"{"name": "rake", "version": "13.2.1", "platform": "ruby"}"#;
        let (executables, native) = spec_matches_plan(&planned, body).unwrap();
        assert!(executables.is_empty());
        assert!(native);
    }
}

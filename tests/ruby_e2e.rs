//! End-to-end Ruby tailor test. Heavy: downloads the pinned portable Ruby
//! and the gem closure (racc compiles a C extension in the sandbox; on
//! Linux, source nokogiri builds its vendored libxml2/libxslt there too).
//!
//! On Linux it is also the Ruby relocation gate:
//! it also records the ELF / RbConfig / pkg-config relocation observations
//! for the realized Ruby object and proves nothing at runtime depends on a
//! staging directory, a Homebrew prefix, or a host Ruby.

// Tests spawn fixtures and take leases freely (see clippy.toml).
#![allow(clippy::disallowed_methods)]

use std::path::{Path, PathBuf};
use std::process::Command;

mod common;

use common::{assert_frozen_never_writes_the_lock, assert_ok, fixture, tog, tog_offline, TempDir};

/// Linux project: only the SOURCE (`ruby` platform) variant of nokogiri, so
/// the gate compiles its vendored libxml2/libxslt in the sandbox instead of
/// silently picking a precompiled `x86_64-linux` gem. Exact versions; the
/// lock is consistent with the Gemfile and carries no CHECKSUMS section, so
/// plan_ruby obtains every digest from the platform-qualified RubyGems API.
fn linux_project_files(project: &Path) {
    std::fs::write(
        project.join("Gemfile"),
        r#"source "https://rubygems.org"

gem "mini_portile2", "2.8.9"
gem "nokogiri", "1.18.10"
gem "racc", "1.8.1"
gem "rake", "13.4.2"
"#,
    )
    .unwrap();
    std::fs::write(
        project.join("Gemfile.lock"),
        r#"GEM
  remote: https://rubygems.org/
  specs:
    mini_portile2 (2.8.9)
    nokogiri (1.18.10)
      mini_portile2 (~> 2.8.2)
      racc (~> 1.4)
    racc (1.8.1)
    rake (13.4.2)

PLATFORMS
  ruby

DEPENDENCIES
  mini_portile2 (= 2.8.9)
  nokogiri (= 1.18.10)
  racc (= 1.8.1)
  rake (= 13.4.2)

BUNDLED WITH
   2.6.9
"#,
    )
    .unwrap();
}

/// Published objects by identity kind: (object path, meta json).
fn find_object(store: &Path, kind: &str) -> Option<(PathBuf, serde_json::Value)> {
    for entry in std::fs::read_dir(store.join("meta")).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let meta: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        if meta["identity"]["kind"].as_str() == Some(kind) {
            let obj = store.join("objects").join(meta["id"].as_str().unwrap());
            return Some((obj, meta));
        }
    }
    None
}

fn assert_immutable_tree(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let metadata = std::fs::symlink_metadata(path).unwrap();
    if metadata.file_type().is_symlink() {
        return;
    }
    assert_eq!(
        metadata.permissions().mode() & 0o222,
        0,
        "published path is writable: {}",
        path.display()
    );
    if metadata.is_dir() {
        for entry in std::fs::read_dir(path).unwrap() {
            assert_immutable_tree(&entry.unwrap().path());
        }
    }
}

/// Prefixes no ACTIVE path may mention: the store's staging area (objects are
/// renamed out of it at commit) and the Homebrew build/host prefixes.
fn forbidden_prefixes(staging: &Path) -> Vec<String> {
    vec![
        staging.to_string_lossy().into_owned(),
        "/home/linuxbrew".to_string(),
        "/opt/homebrew".to_string(),
        "/usr/local/Cellar".to_string(),
    ]
}

fn assert_no_forbidden_prefix(text: &str, staging: &Path, what: &str) {
    for forbidden in forbidden_prefixes(staging) {
        assert!(
            !text.contains(&forbidden),
            "{what} mentions forbidden prefix {forbidden:?}: {text}"
        );
    }
}

/// Run the realized interpreter directly (no tog, scrubbed env) so a
/// host Ruby can never answer for it.
fn pinned_ruby(ruby: &Path, cwd: &Path, script: &str, label: &str) -> String {
    let output = Command::new(ruby.join("bin/ruby"))
        .current_dir(cwd)
        .env_clear()
        .env(
            "PATH",
            format!("{}:/usr/bin:/bin", ruby.join("bin").display()),
        )
        .env("HOME", cwd)
        .env("TMPDIR", cwd)
        .env("BUNDLE_IGNORE_CONFIG", "1")
        .arg("-e")
        .arg(script)
        .output()
        .unwrap();
    assert_ok(output, label)
}

fn tool(name: &str, args: &[&str], target: &Path) -> String {
    let output = Command::new(name).args(args).arg(target).output().unwrap();
    assert_ok(output, &format!("{name} {args:?} {}", target.display()))
}

fn collect_files(root: &Path, suffix: &str, out: &mut Vec<PathBuf>) {
    let Ok(metadata) = std::fs::symlink_metadata(root) else {
        return;
    };
    if metadata.file_type().is_symlink() {
        return;
    }
    if metadata.is_file() {
        if root.to_string_lossy().ends_with(suffix) {
            out.push(root.to_path_buf());
        }
    } else if metadata.is_dir() {
        for entry in std::fs::read_dir(root).unwrap() {
            collect_files(&entry.unwrap().path(), suffix, out);
        }
    }
}

fn collect_symlinks(root: &Path, out: &mut Vec<PathBuf>) {
    let Ok(metadata) = std::fs::symlink_metadata(root) else {
        return;
    };
    if metadata.file_type().is_symlink() {
        out.push(root.to_path_buf());
    } else if metadata.is_dir() {
        for entry in std::fs::read_dir(root).unwrap() {
            collect_symlinks(&entry.unwrap().path(), out);
        }
    }
}

/// glibc sonames the portable bottle, and a gem extension built against the
/// host C runtime alone, may legitimately need from the host. Nothing else:
/// the gem sandbox hides every other host library (`HostView::RuntimeOnly`),
/// so nokogiri's vendored libxml2 finds neither zlib nor liblzma and links
/// glibc only, on every host (issue #304).
fn is_glibc_soname(soname: &str) -> bool {
    [
        "libc.so",
        "libm.so",
        "libdl.so",
        "libpthread.so",
        "librt.so",
        "libcrypt.so",
        "libutil.so",
        "ld-linux-x86-64.so",
    ]
    .iter()
    .any(|prefix| soname.starts_with(prefix))
}

/// `readelf -dW`: NEEDED must be glibc-only; RPATH/RUNPATH is recorded as
/// historical provenance (the bottle retains its Homebrew build RUNPATH but
/// nothing NEEDED lives there). `ldd` then proves what actually resolves.
fn assert_elf_resolves_from_system(elf: &Path, staging: &Path) {
    let dynamic = tool("readelf", &["-dW"], elf);
    for line in dynamic.lines() {
        if line.contains("(NEEDED)") {
            let soname = line
                .rsplit('[')
                .next()
                .unwrap()
                .trim_end_matches(']')
                .trim();
            assert!(
                is_glibc_soname(soname),
                "{} NEEDS a non-glibc library {soname}",
                elf.display()
            );
        } else if line.contains("(RUNPATH)") || line.contains("(RPATH)") {
            eprintln!("{}: historical {}", elf.display(), line.trim());
        }
    }
    let ldd = tool("ldd", &[], elf);
    assert!(
        !ldd.contains("not found"),
        "{} has unresolved libraries:\n{ldd}",
        elf.display()
    );
    assert_no_forbidden_prefix(&ldd, staging, "ldd resolution");
}

/// Relocation observations for the realized Linux Ruby object.
/// Returns the interpreter's own `Gem::Platform.local`.
fn linux_toolchain_observations(project: &Path, ruby: &Path, staging: &Path) -> String {
    let ruby_obj = ruby.canonicalize().unwrap();
    let ruby_binary = ruby_obj.join("bin/ruby");

    let headers = tool("readelf", &["-lW"], &ruby_binary);
    let interpreter = headers
        .lines()
        .find(|line| line.contains("Requesting program interpreter"))
        .expect("bin/ruby has no PT_INTERP");
    eprintln!("bin/ruby {}", interpreter.trim());
    assert_no_forbidden_prefix(interpreter, staging, "program interpreter");
    assert_elf_resolves_from_system(&ruby_binary, staging);

    // Shipped native extensions (portable-ruby links openssl/zlib/yaml/ffi
    // statically into bin/ruby; only bundled gem extensions are .so files).
    let mut shared_objects = Vec::new();
    collect_files(&ruby_obj.join("lib"), ".so", &mut shared_objects);
    for so in &shared_objects {
        assert_elf_resolves_from_system(so, staging);
    }
    eprintln!("Ruby object ships {} .so files", shared_objects.len());

    let config = pinned_ruby(
        &ruby_obj,
        project,
        r#"
require "json"
require "rbconfig"
keys = %w[prefix bindir libdir rubyhdrdir rubyarchhdrdir arch CC CXX LDSHARED LIBRUBYARG ENABLE_SHARED configure_args]
out = keys.to_h { |key| [key, RbConfig::CONFIG[key]] }
out["gem_platform_local"] = Gem::Platform.local.to_s
out["gem_ruby"] = Gem.ruby
out["static_stdlib"] = begin
  require "openssl"
  require "zlib"
  $LOADED_FEATURES.grep(/\A(openssl|zlib)\.so\z/)
end
puts JSON.generate(out)
"#,
        "rbconfig observation",
    );
    let config: serde_json::Value = serde_json::from_str(config.trim()).unwrap();
    let text = |key: &str| config[key].as_str().unwrap_or_default().to_string();
    // Active paths must follow the object (--enable-load-relative).
    assert_eq!(
        Path::new(&text("prefix")).canonicalize().unwrap(),
        ruby_obj,
        "RbConfig prefix does not follow the store object"
    );
    for key in ["bindir", "libdir", "rubyhdrdir", "rubyarchhdrdir"] {
        let value = text(key);
        assert!(
            Path::new(&value).starts_with(&ruby_obj),
            "RbConfig::{key}={value} is outside the object {}",
            ruby_obj.display()
        );
        assert!(
            Path::new(&value).is_dir(),
            "RbConfig::{key}={value} missing"
        );
        assert_no_forbidden_prefix(&value, staging, key);
    }
    for key in [
        "arch",
        "CC",
        "CXX",
        "LDSHARED",
        "LIBRUBYARG",
        "ENABLE_SHARED",
    ] {
        let value = text(key);
        assert!(!value.is_empty(), "RbConfig::{key} is empty");
        assert_no_forbidden_prefix(&value, staging, key);
        eprintln!("RbConfig::{key}={value}");
    }
    assert_eq!(text("gem_ruby"), ruby_binary.to_string_lossy());
    // configure_args retains build provenance (Homebrew Cellar prefix,
    // portable-* dependency dirs). Recorded separately; not an active path.
    eprintln!(
        "RbConfig::configure_args (historical)={}",
        text("configure_args")
    );
    let static_stdlib = config["static_stdlib"].as_array().unwrap();
    assert_eq!(
        static_stdlib.len(),
        2,
        "openssl/zlib were not the statically linked features: {static_stdlib:?}"
    );

    // pkg-config: prefix must be relative to the .pc file and resolve to the
    // object; cflags must point at the object's headers.
    let mut pcs = Vec::new();
    collect_files(&ruby_obj.join("lib/pkgconfig"), ".pc", &mut pcs);
    assert!(!pcs.is_empty(), "portable-ruby shipped no pkg-config file");
    for pc in &pcs {
        let module = pc.file_stem().unwrap().to_str().unwrap();
        let pc_dir = pc.parent().unwrap();
        let pkg_config = |query: &str| {
            let output = Command::new("pkg-config")
                .env("PKG_CONFIG_PATH", pc_dir)
                .args([query, module])
                .output()
                .unwrap();
            assert_ok(output, &format!("pkg-config {query} {module}"))
        };
        let prefix = pkg_config("--variable=prefix");
        assert_eq!(
            Path::new(prefix.trim()).canonicalize().unwrap(),
            ruby_obj,
            "pkg-config {module} prefix does not resolve to the object"
        );
        let cflags = pkg_config("--cflags");
        assert!(
            cflags.contains(&format!("{}/", ruby_obj.display()))
                || cflags.contains("/lib/pkgconfig/../../include"),
            "pkg-config {module} cflags do not reference the object: {cflags}"
        );
        assert_no_forbidden_prefix(&cflags, staging, "pkg-config cflags");
        eprintln!(
            "pkg-config {module}: prefix={} cflags={}",
            prefix.trim(),
            cflags.trim()
        );
    }

    // Native compilation finds the pinned headers via mkmf + host cc (the
    // sandboxed gem build uses the same RbConfig; this is the cheap check).
    let mkmf_dir = project.join("mkmf-probe");
    std::fs::create_dir_all(&mkmf_dir).unwrap();
    let mkmf = pinned_ruby(
        &ruby_obj,
        &mkmf_dir,
        r#"require "mkmf"; $stdout = STDERR; ok = have_header("ruby.h"); STDOUT.puts(ok ? "ruby.h ok" : "ruby.h missing"); exit(ok ? 0 : 1)"#,
        "mkmf header probe",
    );
    assert!(mkmf.contains("ruby.h ok"), "{mkmf}");
    let mkmf_log = std::fs::read_to_string(mkmf_dir.join("mkmf.log")).unwrap_or_default();
    assert!(
        mkmf_log.contains(&format!("-I{}", ruby_obj.join("include").display())),
        "mkmf did not compile against the object's headers:\n{mkmf_log}"
    );
    assert_no_forbidden_prefix(&mkmf_log, staging, "mkmf.log");

    // Launchers: RubyGems' sh-prelude wrappers exec the sibling ruby.
    for launcher in ["bin/gem", "bin/bundle", "bin/bundler"] {
        let body = std::fs::read_to_string(ruby_obj.join(launcher)).unwrap();
        assert!(
            body.starts_with("#!/bin/sh\n"),
            "{launcher} shebang: {:?}",
            body.lines().next()
        );
        assert!(
            body.contains("exec \"$bindir/ruby\""),
            "{launcher} does not exec the sibling interpreter"
        );
        assert_no_forbidden_prefix(&body, staging, launcher);
    }

    let mut symlinks = Vec::new();
    collect_symlinks(&ruby_obj, &mut symlinks);
    for link in &symlinks {
        let target = std::fs::read_link(link).unwrap();
        assert!(
            target.is_relative() || target.starts_with(&ruby_obj),
            "symlink {} escapes the object: {}",
            link.display(),
            target.display()
        );
        assert_no_forbidden_prefix(&target.to_string_lossy(), staging, "symlink target");
    }
    eprintln!("Ruby object symlinks: {}", symlinks.len());

    let platform_local = text("gem_platform_local");
    assert!(!platform_local.is_empty());
    eprintln!(
        "Gem::Platform.local={platform_local}; bottle tag=x86_64_linux; Rust triple=x86_64-unknown-linux-gnu"
    );
    assert_ne!(platform_local, "x86_64_linux");
    assert_ne!(platform_local, "x86_64-unknown-linux-gnu");
    platform_local
}

const STDLIB_PROBE: &str = r#"
require "json"
require "digest"
require "openssl"
require "zlib"
input = "tog-linux-ruby"
compressed = Zlib::Deflate.deflate(input)
abort "zlib round-trip failed" unless Zlib::Inflate.inflate(compressed) == input
digest = OpenSSL::Digest::SHA256.hexdigest(input)
abort "openssl digest disagrees with Digest" unless digest == Digest::SHA256.hexdigest(input)
puts JSON.generate("digest" => digest, "zlib" => "ok", "openssl" => OpenSSL::OPENSSL_LIBRARY_VERSION)
"#;

fn assert_stdlib_probe(output: &str, label: &str) {
    let probe: serde_json::Value = serde_json::from_str(output.trim()).unwrap();
    assert_eq!(probe["zlib"], "ok", "{label}: {output}");
    assert_eq!(
        probe["digest"].as_str().map(str::len),
        Some(64),
        "{label}: {output}"
    );
    assert!(
        probe["openssl"]
            .as_str()
            .unwrap_or_default()
            .starts_with("OpenSSL "),
        "{label}: {output}"
    );
    eprintln!("{label}: {}", output.trim());
}

#[test]
#[ignore]
fn ruby_sync_native_ext_and_run() {
    let linux = cfg!(target_os = "linux");
    let temp = TempDir::new("ruby-e2e");
    let project = temp.0.join("ruby-hello");
    std::fs::create_dir_all(&project).unwrap();
    if linux {
        linux_project_files(&project);
    } else {
        let fixtures = fixture("ruby-hello");
        for f in ["Gemfile", "Gemfile.lock"] {
            std::fs::copy(fixtures.join(f), project.join(f)).unwrap();
        }
    }
    let store = temp.0.join("store");
    let staging = store.join("tmp");

    // Hostile .bundle/config must be neutralized (BUNDLE_IGNORE_CONFIG).
    std::fs::create_dir_all(project.join(".bundle")).unwrap();
    std::fs::write(
        project.join(".bundle/config"),
        "---\nBUNDLE_PATH: \"/nonexistent\"\nBUNDLE_GEMFILE: \"/nonexistent/Gemfile\"\n",
    )
    .unwrap();

    let mut platform_local = String::new();
    if linux {
        // `plan` publishes the Ruby object and prints the gem plan without
        // installing anything, so the toolchain can be gated on its own.
        let plan = assert_ok(tog(&project, &temp.0, &["plan"]), "plan");
        let plan: serde_json::Value = serde_json::from_str(plan.trim())
            .unwrap_or_else(|e| panic!("plan output is not JSON ({e}): {plan}"));
        let gems = plan["gems"].as_array().unwrap();
        let expect = [
            ("mini_portile2", "2.8.9"),
            ("nokogiri", "1.18.10"),
            ("racc", "1.8.1"),
            ("rake", "13.4.2"),
        ];
        assert_eq!(gems.len(), expect.len(), "{plan}");
        for (name, version) in expect {
            let gem = gems
                .iter()
                .find(|g| g["name"] == name)
                .unwrap_or_else(|| panic!("{name} missing from plan: {plan}"));
            assert_eq!(gem["version"], version, "{plan}");
            // Bundler selected the SOURCE gem, not a precompiled platform gem.
            assert_eq!(gem["platform"], "ruby", "{name}: {plan}");
            assert_eq!(gem["full_name"], format!("{name}-{version}"), "{plan}");
            assert_eq!(gem["sha256"].as_str().map(str::len), Some(64), "{plan}");
        }

        let (ruby_obj, _) = find_object(&store, "ruby").expect("Ruby object published by plan");
        assert_immutable_tree(&ruby_obj);
        platform_local = linux_toolchain_observations(&project, &ruby_obj, &staging);
        assert_eq!(
            plan["ruby_platform"].as_str().unwrap(),
            platform_local,
            "plan ruby_platform must be the pinned interpreter's Gem::Platform.local"
        );
        let stdlib = pinned_ruby(
            &ruby_obj,
            &project,
            STDLIB_PROBE,
            "pinned Ruby stdlib probe",
        );
        assert_stdlib_probe(&stdlib, "Toolchain-object stdlib probe");
    }

    // Sandboxed gem realization: racc's C extension, and on Linux nokogiri's
    // vendored libxml2/libxslt, compile here (network denied).
    assert_ok(tog(&project, &temp.0, &["sync"]), "sync");

    let (ruby_obj, _) = find_object(&store, "ruby").expect("Ruby object published");
    let (gems_obj, gems_meta) = find_object(&store, "ruby-gems").expect("gems object published");
    assert_immutable_tree(&ruby_obj);
    assert_immutable_tree(&gems_obj);
    assert!(ruby_obj.join("bin/ruby").is_file());
    assert!(gems_obj.join("gems").is_dir());
    let inputs = gems_meta["identity"]["inputs"].as_object().unwrap();
    if linux {
        assert!(
            inputs.contains_key("gem:nokogiri-1.18.10"),
            "gem object was not built from source nokogiri: {inputs:?}"
        );
        assert!(
            !inputs
                .keys()
                .any(|key| key.starts_with("gem:nokogiri-1.18.10-")),
            "a platform nokogiri gem leaked into the object: {inputs:?}"
        );
        assert_eq!(
            inputs["ruby_platform"].as_str().unwrap(),
            platform_local,
            "gem object platform must be the pinned interpreter's Gem::Platform.local"
        );
        assert_eq!(
            inputs["build_view"].as_str(),
            Some("runtime-only/1"),
            "{inputs:?}"
        );
        // Every native gem here (racc, nokogiri) builds against the host C
        // runtime alone: none fell back to the whole host.
        let exceptions = gems_meta["exceptions"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        assert!(
            !exceptions
                .iter()
                .any(|exception| exception["kind"] == "host-build-inputs"),
            "a gem was rebuilt against the whole host: {exceptions:?}"
        );
    }

    // An unchanged project re-syncs with the network cut. The lock has no
    // CHECKSUMS section, so every digest the plan needs comes from what the
    // first sync verified and recorded in the store, and the same objects
    // are projected again.
    let closure = |project: &Path| -> serde_json::Value {
        serde_json::from_slice(&std::fs::read(project.join(".tog/closures/ruby.json")).unwrap())
            .unwrap()
    };
    let before = closure(&project);
    assert_ok(
        tog_offline(&project, &temp.0, &["sync"]),
        "offline re-sync of the unchanged project",
    );
    let after = closure(&project);
    for key in ["ruby_object", "gems_object"] {
        assert_eq!(
            after["body"][key], before["body"][key],
            "the offline re-sync projected a different {key}"
        );
    }
    // A store whose gem object predates its digest records (or lost them)
    // records them on the next online sync, which only hits the object:
    // each gem is verified again from the artifact cache first. After that
    // the offline re-sync works again.
    let records = store.join("records/rubygems-sha256");
    assert!(records.is_dir(), "the sync recorded no rubygems.org digest");
    tog::kernel::store::remove_tree(&records).unwrap();
    assert_ok(
        tog(&project, &temp.0, &["sync"]),
        "sync over the gem object",
    );
    assert!(
        std::fs::read_dir(&records).unwrap().count() > 0,
        "an object hit recorded no rubygems.org digest"
    );
    assert_ok(
        tog_offline(&project, &temp.0, &["sync"]),
        "offline re-sync after an object hit recorded the digests",
    );

    // Nothing that follows may depend on a staging directory: after the
    // commits, clear whatever is left under store/tmp.
    if let Ok(entries) = std::fs::read_dir(&staging) {
        for entry in entries {
            let path = entry.unwrap().path();
            let _ = tog::kernel::store::remove_tree(&path);
            let _ = std::fs::remove_file(&path);
        }
    }
    assert!(
        std::fs::read_dir(&staging)
            .map(|mut d| d.next().is_none())
            .unwrap_or(true),
        "staging directory still populated"
    );

    if linux {
        let stdlib = assert_ok(
            tog(&project, &temp.0, &["run", "ruby", "-e", STDLIB_PROBE]),
            "committed Ruby stdlib probe",
        );
        assert_stdlib_probe(&stdlib, "Projected-env stdlib probe");
    }

    // racc's C extension compiled in the sandbox; requiring it proves the
    // native extension (.bundle on Darwin, .so on Linux) stayed loadable and
    // the projected env works.
    let out = assert_ok(
        tog(
            &project,
            &temp.0,
            &[
                "run",
                "ruby",
                "-e",
                "require \"racc/parser\"; require \"rake\"; puts \"ok \" + Rake::VERSION",
            ],
        ),
        "run",
    );
    assert!(out.trim().starts_with("ok 13."), "{out}");
    // The binstub that runs must be the STORE object's wrapper, not a host
    // /usr/bin fallback: a symlink binstub that dangles after the commit
    // rename would otherwise let host rake answer and the check still pass.
    let which = assert_ok(
        tog(&project, &temp.0, &["run", "sh", "-c", "command -v rake"]),
        "which rake",
    );
    let which = which.trim().to_string();
    assert!(
        which.contains("/objects/") && which.contains("gems"),
        "rake resolved outside the store: {which}"
    );
    assert_eq!(
        Path::new(&which).canonicalize().unwrap(),
        gems_obj.canonicalize().unwrap().join("bin/rake"),
        "rake is not the gem object's binstub: {which}"
    );
    // The wrapper itself must execute (relocatable, not a dangling link).
    // Pass the absolute store path as argv[0]; no shell that could quietly
    // fall back to /usr/bin/rake.
    let direct = tog(&project, &temp.0, &["run", which.as_str(), "--version"]);
    let version = assert_ok(direct, "store binstub direct exec");
    assert!(version.contains("13."), "{version}");

    if linux {
        let nokogiri = assert_ok(
            tog(
                &project,
                &temp.0,
                &[
                    "run",
                    "ruby",
                    "-e",
                    r#"
require "json"
require "nokogiri"
xml = Nokogiri::XML("<root><value>ok</value></root>")
value = xml.at_xpath("/root/value").text
native = $LOADED_FEATURES.find { |path| path.end_with?(".so") && File.basename(path) == "nokogiri.so" }
abort "nokogiri native library was not loaded" unless native
info = Nokogiri::VERSION_INFO
puts JSON.generate("native" => File.realpath(native), "value" => value,
  "nokogiri" => info["nokogiri"]["version"], "libxml_source" => info["libxml"]["source"],
  "libxml" => info["libxml"]["loaded"], "libxslt_source" => info.dig("libxslt", "source"))
"#,
                ],
            ),
            "nokogiri native extension probe",
        );
        let nokogiri: serde_json::Value = serde_json::from_str(nokogiri.trim()).unwrap();
        eprintln!("nokogiri probe: {nokogiri}");
        assert_eq!(nokogiri["value"], "ok");
        assert_eq!(nokogiri["nokogiri"], "1.18.10");
        // Vendored-library source build, not system libxml2 and not a
        // precompiled gem.
        assert_eq!(nokogiri["libxml_source"], "packaged", "{nokogiri}");
        assert_eq!(nokogiri["libxslt_source"], "packaged", "{nokogiri}");
        let native = nokogiri["native"].as_str().unwrap();
        assert!(
            native.ends_with(".so"),
            "not a Linux native library: {native}"
        );
        assert!(
            Path::new(native).starts_with(gems_obj.canonicalize().unwrap()),
            "nokogiri loaded outside the committed gem object: {native}"
        );
        assert_no_forbidden_prefix(native, &staging, "nokogiri native library");
        assert_elf_resolves_from_system(Path::new(native), &staging);
    }
    // Without its lock the project is refused under --frozen and left
    // alone; a plan regenerates the lock with the store bundler.
    assert_frozen_never_writes_the_lock(&project, &temp.0, "Gemfile.lock");
}

/// Linux project whose only gem is the source `zlib` gem. Its extension
/// needs the host's `zlib.h` and `libz.so`, which the C-runtime-only view
/// hides, and it bundles no zlib source of its own, so its hermetic build
/// fails and it falls back to the whole host.
fn zlib_project_files(project: &Path) {
    std::fs::write(
        project.join("Gemfile"),
        r#"source "https://rubygems.org"

gem "zlib", "3.2.3"
"#,
    )
    .unwrap();
    std::fs::write(
        project.join("Gemfile.lock"),
        r#"GEM
  remote: https://rubygems.org/
  specs:
    zlib (3.2.3)

PLATFORMS
  ruby

DEPENDENCIES
  zlib (= 3.2.3)

BUNDLED WITH
   2.6.9
"#,
    )
    .unwrap();
}

/// A gem that needs host development packages still installs: it falls
/// back to the whole host, the object is committed under its own
/// `host-fallback/1` identity with a `host-build-inputs` exception naming
/// the gem, and the next sync finds that object through the store record
/// instead of building again (issue #304).
#[test]
#[ignore]
#[cfg(target_os = "linux")]
fn ruby_gem_needing_host_headers_falls_back_once() {
    if !Path::new("/usr/include/zlib.h").is_file() {
        eprintln!("skipped: this host has no /usr/include/zlib.h (zlib development package)");
        return;
    }
    const ZLIB_SHA256: &str = "5bd316698b32f31a64ab910a8b6c282442ca1626a81bbd6a1674e8522e319c20";
    let temp = TempDir::new("ruby-e2e-fallback");
    let project = temp.0.join("ruby-zlib");
    std::fs::create_dir_all(&project).unwrap();
    zlib_project_files(&project);
    let store = temp.0.join("store");

    assert_ok(tog(&project, &temp.0, &["sync"]), "sync");
    let (gems_obj, gems_meta) = find_object(&store, "ruby-gems").expect("gems object published");
    assert_immutable_tree(&gems_obj);
    let inputs = gems_meta["identity"]["inputs"].as_object().unwrap();
    assert_eq!(
        inputs["gem:zlib-3.2.3"].as_str(),
        Some(ZLIB_SHA256),
        "{inputs:?}"
    );
    assert_eq!(
        inputs["build_view"].as_str(),
        Some("host-fallback/1"),
        "{inputs:?}"
    );
    assert_eq!(
        inputs["host_fallback"].as_str(),
        Some("zlib-3.2.3"),
        "{inputs:?}"
    );
    let exceptions = gems_meta["exceptions"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        exceptions
            .iter()
            .any(|exception| exception["kind"] == "host-build-inputs"
                && exception["subject"] == "zlib-3.2.3"),
        "no host-build-inputs exception for zlib-3.2.3: {exceptions:?}"
    );
    // The extension was built against the host's libz.
    let mut extensions = Vec::new();
    collect_files(&gems_obj.join("extensions"), "/zlib.so", &mut extensions);
    assert_eq!(extensions.len(), 1, "{extensions:?}");
    let dynamic = tool("readelf", &["-dW"], &extensions[0]);
    assert!(dynamic.contains("[libz.so.1]"), "{dynamic}");
    let records = store.join("records/ruby-gems-host-fallback");
    assert_eq!(
        std::fs::read_dir(&records).unwrap().count(),
        1,
        "the fallback was not recorded"
    );

    // The next sync reaches the fallback object through the record, never
    // by building again: with the `.gem` gone from the artifact cache and
    // the network cut, a rebuild could not even start.
    let closure = |project: &Path| -> serde_json::Value {
        serde_json::from_slice(&std::fs::read(project.join(".tog/closures/ruby.json")).unwrap())
            .unwrap()
    };
    let before = closure(&project);
    let cached = store.join("cache/sha256").join(ZLIB_SHA256);
    assert!(cached.exists(), "the zlib gem is not in the artifact cache");
    tog::kernel::store::remove_tree(&cached)
        .or_else(|_| std::fs::remove_file(&cached))
        .unwrap();
    let second = assert_ok(
        tog_offline(&project, &temp.0, &["sync"]),
        "offline re-sync over the fallback object",
    );
    eprintln!("second sync: {second}");
    let after = closure(&project);
    assert_eq!(
        after["body"]["gems_object"], before["body"]["gems_object"],
        "the re-sync projected a different gems object"
    );
    assert_eq!(
        after["body"]["gems_object"]["id"], gems_meta["id"],
        "{after}"
    );
}

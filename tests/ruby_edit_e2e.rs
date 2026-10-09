//! Dependency edits must not run native gem builds outside Tog's sandbox.
#![allow(clippy::disallowed_methods)]

use std::path::Path;

mod common;
use common::{assert_ok, command, TempDir};

fn path_gem(project: &Path, directory: &str, name: &str, native: bool) {
    let gem = project.join(directory);
    std::fs::create_dir_all(gem.join("lib")).unwrap();
    std::fs::write(gem.join("lib/fixture.rb"), "# fixture\n").unwrap();
    let extension = if native {
        std::fs::create_dir(gem.join("ext")).unwrap();
        std::fs::write(
            gem.join("ext/extconf.rb"),
            "File.write(File.expand_path('../../native-build-ran', __dir__), 'ran')\n\
             abort 'native build must not run during a dependency edit'\n",
        )
        .unwrap();
        "s.extensions = ['ext/extconf.rb']\n"
    } else {
        ""
    };
    std::fs::write(
        gem.join(format!("{name}.gemspec")),
        format!(
            "Gem::Specification.new do |s|\n\
             s.name = '{name}'\n\
             s.version = '9.9.9'\n\
             s.summary = 'Tog regression fixture'\n\
             s.authors = ['Tog']\n\
             s.files = Dir['lib/**/*', 'ext/**/*']\n\
             {extension}end\n"
        ),
    )
    .unwrap();
}

#[test]
#[ignore]
fn removing_one_gem_does_not_build_the_native_gem_left_behind() {
    let temp = TempDir::new("ruby-edit-no-install");
    let project = &temp.0.join("project");
    let home = temp.0.join("home");
    let store = temp.0.join("store");
    std::fs::create_dir(project).unwrap();
    std::fs::create_dir(&home).unwrap();
    path_gem(project, "native", "native-sentinel", true);
    path_gem(project, "removable", "rainbow", false);
    std::fs::write(
        project.join("Gemfile"),
        "require 'bundler/installer'\n\
         class << Bundler::Installer\n\
           def install(*)\n\
             File.write(File.join(__dir__, 'install-ran'), 'attempt')\n\
             abort 'dependency edit invoked the Bundler installer'\n\
           end\n\
         end\n\
         source 'https://rubygems.org'\n\
         gem 'native-sentinel', path: './native'\n\
         gem 'rainbow', path: './removable'\n",
    )
    .unwrap();
    let run = |args: &[&str]| command(project, &home, &store).args(args).output().unwrap();
    assert_ok(
        run(&["update", "--no-sync"]),
        "initial lock without install",
    );
    assert!(!project.join("native-build-ran").exists());
    let output = run(&["remove", "--no-sync", "rainbow"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "remove installed a native gem: {stderr}"
    );
    assert!(
        !project.join("native-build-ran").exists(),
        "native build ran"
    );
    let gemfile = std::fs::read_to_string(project.join("Gemfile")).unwrap();
    let lock = std::fs::read_to_string(project.join("Gemfile.lock")).unwrap();
    assert!(gemfile.contains("native-sentinel") && !gemfile.contains("rainbow"));
    assert!(
        lock.contains("native-sentinel (9.9.9)") && !lock.contains("rainbow"),
        "{lock}"
    );
}

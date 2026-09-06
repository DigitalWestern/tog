//! Install-time artifact policy (NEXT.md item 5).
//!
//! Install scripts run with the network denied, so a package that downloads
//! something at install time fails unless blanket does one of three things:
//! provision the file first (declared artifacts, see `BlanketConfig`), tell the
//! installer to skip the download, or make it build from source. This module
//! holds the second and third: a small table of packages whose skip switch is
//! documented by the package itself, and detection of the prebuilt-binary
//! downloaders that already know how to compile instead.
//!
//! Every entry's environment variable was read out of the package's own
//! source, not from memory; add entries the same way.

/// A package whose installer has a documented "do not download" switch.
pub struct SkipDownload {
    pub name: &'static str,
    pub envs: &'static [(&'static str, &'static str)],
    /// What the user runs later to get the artifact, named in the exception.
    pub hint: &'static str,
}

/// Verified against each package's published source on 2026-09-06.
pub const SKIP_DOWNLOADS: &[SkipDownload] = &[
    SkipDownload {
        // lib/puppeteer/getConfiguration.js: getBooleanEnvVar('PUPPETEER_SKIP_DOWNLOAD')
        name: "puppeteer",
        envs: &[("PUPPETEER_SKIP_DOWNLOAD", "true")],
        hint: "npx puppeteer browsers install chrome",
    },
    SkipDownload {
        // puppeteer-core has no install script; the switch is harmless there
        // and keeps older pinned versions (which did) consistent.
        name: "puppeteer-core",
        envs: &[("PUPPETEER_SKIP_DOWNLOAD", "true")],
        hint: "npx puppeteer browsers install chrome",
    },
    SkipDownload {
        // dist/: CYPRESS_INSTALL_BINARY, "0" means do not download the binary.
        name: "cypress",
        envs: &[("CYPRESS_INSTALL_BINARY", "0")],
        hint: "npx cypress install",
    },
];

pub fn skip_download_for(name: &str) -> Option<&'static SkipDownload> {
    SKIP_DOWNLOADS.iter().find(|entry| entry.name == name)
}

/// Prebuilt-binary downloaders that fall back to compiling from source.
///
/// `prebuild-install`, `node-pre-gyp` and friends try a network download first
/// and only then run `node-gyp rebuild`. With the network denied the download
/// fails anyway, so asking for the source build up front skips a doomed fetch
/// and, more importantly, keeps the failure legible when the compile is what
/// actually breaks.
const SOURCE_BUILD_MARKERS: &[&str] = &[
    "prebuild-install",
    "node-pre-gyp",
    "@mapbox/node-pre-gyp",
    "prebuildify",
];

/// Whether this package's install script hands off to a prebuilt-binary
/// downloader. Packages with declared artifacts are excluded: their bytes were
/// planted where the downloader's cache lookup will find them, and forcing a
/// source build would make it ignore them.
pub fn wants_source_build(script_text: &str, has_declared_artifacts: bool) -> bool {
    if has_declared_artifacts {
        return false;
    }
    SOURCE_BUILD_MARKERS
        .iter()
        .any(|marker| script_text.contains(marker))
}

/// The environment that makes a prebuilt-binary downloader compile instead.
pub fn source_build_envs() -> Vec<(String, String)> {
    vec![
        ("npm_config_build_from_source".to_string(), "true".to_string()),
        // node-pre-gyp reads this spelling; prebuild-install reads the npm_config one.
        ("BUILD_FROM_SOURCE".to_string(), "true".to_string()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skip_table_is_unique_and_populated() {
        let mut names = std::collections::HashSet::new();
        for entry in SKIP_DOWNLOADS {
            assert!(names.insert(entry.name), "duplicate entry: {}", entry.name);
            assert!(!entry.envs.is_empty(), "{} has no switch", entry.name);
            assert!(!entry.hint.is_empty(), "{} has no hint", entry.name);
        }
        assert!(skip_download_for("puppeteer").is_some());
        assert!(skip_download_for("not-a-real-package").is_none());
    }

    #[test]
    fn source_build_is_detected_from_the_script_text() {
        assert!(wants_source_build("prebuild-install || node-gyp rebuild", false));
        assert!(wants_source_build("node-pre-gyp install --fallback-to-build", false));
        assert!(!wants_source_build("node-gyp rebuild", false));
        assert!(!wants_source_build("echo hello", false));
        // Declared artifacts win: the bytes are already where the downloader
        // looks, so it must not be told to ignore them.
        assert!(!wants_source_build("prebuild-install || node-gyp rebuild", true));
    }
}

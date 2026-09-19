//! Install-time artifact policy.
//!
//! Install scripts run with the network denied, so a package that downloads
//! something at install time fails unless blanket does one of three things:
//! provision the file first (declared artifacts, see `BlanketConfig`), tell the
//! installer to skip the download, or make it build from source. All three
//! live here: provisioning for electron, a small table of packages whose skip
//! switch is documented by the package itself, and detection of the
//! prebuilt-binary downloaders that already know how to compile instead.
//!
//! Every entry's environment variable was read out of the package's own
//! source, not from memory; add entries the same way.

use crate::kernel::platform::Platform;
use crate::kernel::store::Store;
use std::fs;
use std::io;
use std::path::Path;
/// A package whose installer has a documented "do not download" switch.
pub struct SkipDownload {
    pub name: &'static str,
    pub envs: &'static [(&'static str, &'static str)],
    /// What the user runs later to get the artifact, named in the exception.
    pub hint: &'static str,
}

/// Every entry was verified against the package's published source.
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
        (
            "npm_config_build_from_source".to_string(),
            "true".to_string(),
        ),
        // node-pre-gyp reads this spelling; prebuild-install reads the npm_config one.
        ("BUILD_FROM_SOURCE".to_string(), "true".to_string()),
    ]
}

/// Provisioning: blanket downloads the artifact itself, verifies it, and puts
/// it where the installer's own cache lookup finds it, so the package is
/// really installed rather than skipped.
///
/// Electron first. Every detail below was read out of `@electron/get`'s
/// published source rather than guessed:
/// - `install.js` passes `cacheRoot: process.env.electron_config_cache`.
/// - `Cache.getCacheDirectory(url)` is the sha256 of the download URL with its
///   query and fragment cleared and its path replaced by the path's dirname —
///   that is, the release directory URL.
/// - the file is cached under its own name, and the zip is verified against a
///   `SHASUMS256.txt` that `@electron/get` reads from the same cache, so both
///   files must be present for an offline install.
pub struct Provisioning {
    pub envs: Vec<(String, String)>,
    /// (subject, detail) pairs the caller records as policy exceptions.
    pub records: Vec<(String, String)>,
}

fn electron_platform(platform: Platform) -> (&'static str, &'static str) {
    match platform {
        Platform::Aarch64AppleDarwin => ("darwin", "arm64"),
        Platform::X86_64UnknownLinuxGnu => ("linux", "x64"),
    }
}

/// The cache directory name `@electron/get` derives from a download URL.
pub fn electron_cache_directory(release_url: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(release_url.as_bytes()))
}

/// Resolve electron's zip name and sha256 for this platform, caching the
/// release's checksum manifest in the store.
///
/// The result is an identity input (a GitHub release asset can be replaced,
/// so the version alone does not determine the bytes), which is why this is
/// separate from placement and why the manifest is cached: an environment
/// identity must not need the network on a warm store.
fn resolve_electron(
    store: &Store,
    platform: Platform,
    version: &str,
) -> io::Result<(String, String, String, String)> {
    let (os, arch) = electron_platform(platform);
    let release_url = format!("https://github.com/electron/electron/releases/download/v{version}");
    let zip_name = format!("electron-v{version}-{os}-{arch}.zip");
    let cached = store
        .root
        .join("cache/electron-shasums")
        .join(electron_cache_directory(&release_url));
    let sums = match fs::read_to_string(cached.join("SHASUMS256.txt")) {
        Ok(text) => text,
        Err(_) => {
            let sums_url = format!("{release_url}/SHASUMS256.txt");
            // Trust-on-first-use over HTTPS, exactly like the pinned toolchain
            // tables: this IS the checksum source. The zip is then verified
            // against it, so a corrupted or swapped zip fails.
            let text = crate::kernel::fetch::fetch_text(&sums_url).map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!("electron {version}: fetch {sums_url}: {e}"),
                )
            })?;
            fs::create_dir_all(&cached)?;
            fs::write(cached.join("SHASUMS256.txt"), text.as_bytes())?;
            text
        }
    };
    let sha256 = sums
        .lines()
        .find_map(|line| {
            let (hash, file) = line.split_once(char::is_whitespace)?;
            (file.trim_start_matches('*') == zip_name).then(|| hash.trim().to_ascii_lowercase())
        })
        .filter(|hash| hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit()))
        .ok_or_else(|| {
            io::Error::other(format!(
                "electron {version}: {zip_name} is not listed in SHASUMS256.txt"
            ))
        })?;
    Ok((sha256, sums, release_url, zip_name))
}

/// The one decision behind every `provisioned:` identity input: does the
/// producer provision an artifact for this package at all? Returns the
/// normalized version it would resolve. The producer and the `node-env`
/// identity contract both consult this, so the contract can require the
/// `provisioned:` key exactly when the producer writes one.
pub fn provisioned_version<'a>(name: &str, version: &'a str) -> Option<&'a str> {
    if name != "electron" {
        return None;
    }
    let version = version.trim_start_matches('v');
    if !version.starts_with(|c: char| c.is_ascii_digit())
        || !crate::kernel::gitsrc::is_safe_component(version)
    {
        return None;
    }
    Some(version)
}

pub fn provisioned_identity_input(
    store: &Store,
    platform: Platform,
    name: &str,
    version: &str,
) -> io::Result<Option<String>> {
    let Some(version) = provisioned_version(name, version) else {
        return Ok(None);
    };
    let (sha256, _, _, zip_name) = resolve_electron(store, platform, version)?;
    Ok(Some(format!("{zip_name}:{sha256}")))
}

pub fn provision(
    store: &Store,
    platform: Platform,
    name: &str,
    version: &str,
    scratch: &Path,
) -> io::Result<Option<Provisioning>> {
    if name != "electron" {
        return Ok(None);
    }
    let version = version.trim_start_matches('v');
    // The version comes from a lockfile, which is attacker-editable. It is
    // interpolated into the release URL and into a filename, so anything but a
    // plain version string is refused before either is built: otherwise
    // `1/../../../someone/else/releases/download/v1` resolves to another
    // repository's release (self-consistent zip AND checksum manifest), and a
    // `/../` in the filename writes the fetched bytes outside the cache dir.
    if !version.starts_with(|c: char| c.is_ascii_digit())
        || !crate::kernel::gitsrc::is_safe_component(version)
    {
        return Ok(None);
    }
    let (sha256, sums, release_url, zip_name) = resolve_electron(store, platform, version)?;
    let zip = crate::kernel::fetch::download_verified_held(
        store,
        &format!("{release_url}/{zip_name}"),
        &sha256,
    )?;

    let cache_root = scratch.join(".cache/blanket-electron");
    let dir = cache_root.join(electron_cache_directory(&release_url));
    fs::create_dir_all(&dir)?;
    // Belt and braces: the destination must still be inside the cache dir.
    let zip_dest = dir.join(&zip_name);
    if zip_dest.parent() != Some(dir.as_path()) {
        return Err(io::Error::other(format!(
            "refusing to write {} outside {}",
            zip_dest.display(),
            dir.display()
        )));
    }
    fs::copy(&*zip, &zip_dest)?;
    fs::write(dir.join("SHASUMS256.txt"), sums.as_bytes())?;

    Ok(Some(Provisioning {
        envs: vec![(
            "electron_config_cache".to_string(),
            cache_root.display().to_string(),
        )],
        records: vec![(
            format!("electron@{version}"),
            format!("provisioned {zip_name} (sha256 {sha256}) from upstream SHASUMS256.txt"),
        )],
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_electron_cache_directory_matches_electron_gets_own_rule() {
        // @electron/get hashes the download URL with query and fragment
        // cleared and the path replaced by its dirname — i.e. the release
        // directory URL. Golden computed independently:
        //   sha256("https://github.com/electron/electron/releases/download/v39.0.0")
        assert_eq!(
            electron_cache_directory(
                "https://github.com/electron/electron/releases/download/v39.0.0"
            ),
            "4085417ef19dc0c699e7ae20aa4c47fda5a93b6d7926668b0c472c4233ed07e0"
        );
    }

    #[test]
    fn electron_artifacts_are_named_per_platform() {
        assert_eq!(
            electron_platform(Platform::X86_64UnknownLinuxGnu),
            ("linux", "x64")
        );
        assert_eq!(
            electron_platform(Platform::Aarch64AppleDarwin),
            ("darwin", "arm64")
        );
    }

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
        assert!(wants_source_build(
            "prebuild-install || node-gyp rebuild",
            false
        ));
        assert!(wants_source_build(
            "node-pre-gyp install --fallback-to-build",
            false
        ));
        assert!(!wants_source_build("node-gyp rebuild", false));
        assert!(!wants_source_build("echo hello", false));
        // Declared artifacts win: the bytes are already where the downloader
        // looks, so it must not be told to ignore them.
        assert!(!wants_source_build(
            "prebuild-install || node-gyp rebuild",
            true
        ));
    }
}

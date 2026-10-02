//! `tog update --self`: replace this binary with the newest GitHub release,
//! and the `version` row `tog doctor` prints.
//!
//! The release is whatever GitHub calls the latest release of the
//! repository, read from its releases API (one request, JSON). The asset
//! names, the `.sha256` file next to each asset, and the "copy to a sibling
//! and rename" install are the rules `install.sh` follows, so a binary the
//! script installed and one this verb installed are the same bytes at the
//! same path. Nothing here opens the store or reads a project.
//!
//! `TOG_RELEASE_MANIFEST` names another manifest URL (a `file://` path in
//! the tests) and is the only way tog talks to anything but GitHub here.

use crate::cli;
use crate::commands::inspect::{Check, Level};
use crate::kernel::archive::{self, Compression};
use crate::kernel::fetch;
use crate::kernel::platform::Platform;
use crate::kernel::ui;
use serde_json::Value;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

const RELEASES_API: &str = "https://api.github.com/repos/DigitalWestern/tog/releases/latest";
const RELEASES_PAGE: &str = "https://github.com/DigitalWestern/tog/releases";
/// How long the one-shot lookup may take. `doctor` runs it on every
/// invocation, so a slow or black-holed network must cost seconds, not
/// minutes; the download that follows a real update is not bounded.
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(10);

/// Where the latest-release manifest is read from.
pub fn manifest_url() -> String {
    std::env::var("TOG_RELEASE_MANIFEST")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| RELEASES_API.to_string())
}

/// A version as `install.sh` and the release tag spell it: `v0.2.0`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version(u64, u64, u64);

impl Version {
    /// Accepts `0.2.0` and `v0.2.0`; refuses anything else, including a
    /// pre-release suffix, because a tag tog cannot order is not one it
    /// should offer to install.
    pub fn parse(text: &str) -> Option<Version> {
        let text = text.trim().strip_prefix('v').unwrap_or(text.trim());
        let mut parts = text.split('.').map(|part| {
            if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
                None
            } else {
                part.parse::<u64>().ok()
            }
        });
        let version = Version(parts.next()??, parts.next()??, parts.next()??);
        if parts.next().is_some() {
            return None;
        }
        Some(version)
    }

    /// The crate version this binary was built from. An error rather than
    /// a panic when Cargo.toml carries a pre-release suffix one day: the
    /// verb has nothing to compare against, and says so.
    pub fn running() -> io::Result<Version> {
        Version::parse(cli::VERSION).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "this build's version '{}' is not x.y.z, so it cannot be compared with a release",
                    cli::VERSION
                ),
            )
        })
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.0, self.1, self.2)
    }
}

/// What the manifest said: the tag, its version, and the downloadable
/// assets by file name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Release {
    pub tag: String,
    pub version: Version,
    pub assets: Vec<(String, String)>,
}

impl Release {
    /// The manifest is GitHub's `releases/latest` document; only `tag_name`
    /// and each asset's `name` and `browser_download_url` are read.
    pub fn parse(text: &str) -> io::Result<Release> {
        let value: Value = serde_json::from_str(text).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("the release manifest is not JSON: {error}"),
            )
        })?;
        let tag = value["tag_name"]
            .as_str()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "the release manifest has no tag_name",
                )
            })?
            .to_string();
        let version = Version::parse(&tag).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("the release tag '{tag}' is not a version (expected vX.Y.Z)"),
            )
        })?;
        let assets = value["assets"]
            .as_array()
            .map(|assets| {
                assets
                    .iter()
                    .filter_map(|asset| {
                        Some((
                            asset["name"].as_str()?.to_string(),
                            asset["browser_download_url"].as_str()?.to_string(),
                        ))
                    })
                    .collect()
            })
            .unwrap_or_default();
        Ok(Release {
            tag,
            version,
            assets,
        })
    }

    fn asset(&self, name: &str) -> Option<&str> {
        self.assets
            .iter()
            .find(|(asset, _)| asset == name)
            .map(|(_, url)| url.as_str())
    }
}

/// Read the latest release. The only network request `doctor` makes.
pub fn latest() -> io::Result<Release> {
    let url = manifest_url();
    let text = fetch::fetch_text_within(&url, Some(LOOKUP_TIMEOUT))
        .map_err(|error| no_release_found(&url, error))?;
    Release::parse(&text)
}

/// A 404 on the release manifest means the server shows no release there:
/// none is published, or the repository is private and this request is
/// anonymous. `kernel::fetch` explains a 404 as a yanked package or a
/// stale lockfile, which is wrong here: nothing was yanked and no lockfile
/// is involved.
fn no_release_found(url: &str, error: io::Error) -> io::Error {
    match fetch::http_status(&error) {
        Some(404) => io::Error::new(
            io::ErrorKind::NotFound,
            format!("no published release at {url}; the server answered 404"),
        ),
        _ => error,
    }
}

/// The `version` row of `tog doctor`: this build, and whether a newer
/// release exists. Offline, or with a manifest tog cannot read, the row
/// says the check did not happen and stays `ok`: a laptop on a plane is
/// not unhealthy, and a CI job must not fail on GitHub's rate limit.
///
/// A release is compared by version only. A release does not name the
/// commit it was built from, so a local build of the same crate version
/// (from an older or a newer commit) reads as "same version", and the row
/// says so rather than calling it current.
pub fn doctor_check() -> Check {
    let running = cli::version_line();
    let current = match Version::running() {
        Ok(current) => current,
        Err(error) => {
            return Check {
                name: "version",
                level: Level::Warn,
                detail: format!("{running}; {error}"),
            }
        }
    };
    match latest() {
        Ok(release) if release.version > current => Check {
            name: "version",
            level: Level::Warn,
            detail: format!(
                "{running}; {} is out (run 'tog update --self')",
                release.tag
            ),
        },
        Ok(release) if release.version == current => Check {
            name: "version",
            level: Level::Ok,
            detail: format!(
                "{running}; the latest release is {} (same version; releases are compared by version, not by commit)",
                release.tag
            ),
        },
        Ok(release) => Check {
            name: "version",
            level: Level::Ok,
            detail: format!(
                "{running}; newer than the latest release, {}",
                release.tag
            ),
        },
        Err(error) => Check {
            name: "version",
            level: Level::Ok,
            detail: format!("{running}; newer release not checked ({error})"),
        },
    }
}

/// The file to replace: the running binary with every symlink followed.
/// `~/.local/bin/tog -> ~/src/tog/target/release/tog` gets a new file at
/// the target, which the final line names, so nobody is surprised. (Linux
/// already reports the resolved path; macOS may report the link.)
fn running_binary() -> io::Result<PathBuf> {
    let exe = std::env::current_exe().map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("cannot locate the running tog: {error}"),
        )
    })?;
    fs::canonicalize(&exe).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("cannot resolve {}: {error}", exe.display()),
        )
    })
}

/// A name no other process, and no earlier run of this one, could have
/// left behind: pid, a nanosecond clock, and a per-process counter. Every
/// path below is created with `create_new` on top of that, so a name that
/// does exist (a stale file, or one planted by another user in a shared
/// temporary directory) is refused rather than opened.
fn unique_suffix() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or(0);
    format!(
        "{}.{nanos}.{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    )
}

/// A scratch directory in the system temporary directory, created fresh
/// (mode 0700, never an existing path, so a symlink planted under a
/// guessable name is never followed) and removed on every exit path.
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> io::Result<Scratch> {
        use std::os::unix::fs::DirBuilderExt;
        let path = std::env::temp_dir().join(format!("tog-update-{}", unique_suffix()));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .map_err(|error| {
                io::Error::new(error.kind(), format!("create {}: {error}", path.display()))
            })?;
        Ok(Scratch(path))
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// The sibling the new binary is written to before the rename, removed on
/// every path but the rename that consumes it. Creating it is the
/// writability probe: it happens before anything is downloaded, so a
/// refused update touches nothing but this one file, and the refusal names
/// the directory the user has to make writable or the installer they
/// should use instead. `create_new` means an existing file under the name
/// is an error, never something written through.
struct Stage {
    path: PathBuf,
    armed: bool,
}

impl Stage {
    fn create(target: &Path) -> io::Result<(Stage, fs::File)> {
        use std::os::unix::fs::OpenOptionsExt;
        let dir = target.parent().ok_or_else(|| {
            io::Error::other(format!("{} has no parent directory", target.display()))
        })?;
        let path = dir.join(format!(".tog.update.{}", unique_suffix()));
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o755)
            .open(&path)
        {
            Ok(file) => Ok((Stage { path, armed: true }, file)),
            Err(error) => Err(io::Error::new(
                error.kind(),
                format!(
                    "cannot write to {} ({error}); tog is installed there. Make that directory \
                     writable, or install a copy you own:\n  curl -fsSL \
                     https://raw.githubusercontent.com/DigitalWestern/tog/main/install.sh | sh",
                    dir.display()
                ),
            )),
        }
    }

    /// The rename took the file: nothing left to remove.
    fn consumed(mut self) {
        self.armed = false;
    }
}

impl Drop for Stage {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

/// The digest `install.sh` reads, read the same way: the text before the
/// first space, and the line ending dropped. The digest is compared as
/// written, lower-case hex, because that is what `sha256sum` and `shasum`
/// print and what the installer compares against.
fn parse_sha256(text: &str, asset: &str) -> io::Result<String> {
    let digest = text
        .split(' ')
        .next()
        .unwrap_or("")
        .trim_end_matches(['\r', '\n'])
        .to_string();
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("the checksum file for {asset} does not hold a sha256; refusing to install an unverified binary"),
        ));
    }
    Ok(digest)
}

/// `<binary> --version`, so a download that does not run on this machine,
/// or that is not the release it was published as, is refused before it
/// replaces a binary that works.
// Reviewed site (tests/architecture.rs): runs the downloaded tog before it is installed; no store.
#[allow(clippy::disallowed_methods)]
fn smoke_test(binary: &Path, expected: Version) -> io::Result<String> {
    let output = Command::new(binary)
        .arg("--version")
        .env("NO_COLOR", "1")
        .output()
        .map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("the downloaded tog does not run on this machine ({error})"),
            )
        })?;
    let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if !output.status.success() || !text.starts_with("tog ") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "the downloaded tog does not identify itself ({}; printed {text:?}); the current binary is untouched",
                output.status
            ),
        ));
    }
    let reported = text.split(' ').nth(1).and_then(Version::parse);
    if reported != Some(expected) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "the downloaded tog says it is {}, not {expected} (printed {text:?}); the release's asset does not match its tag, and the current binary is untouched",
                reported.map_or_else(|| "no version".to_string(), |v| v.to_string())
            ),
        ));
    }
    Ok(text)
}

pub fn run(platform: Platform) -> io::Result<i32> {
    let running = cli::version_line();
    let target = running_binary()?;
    let release = latest().map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("cannot read the latest release ({error}); releases: {RELEASES_PAGE}"),
        )
    })?;
    let current = Version::running()?;
    if release.version == current {
        ui::note(&format!(
            "{running} is at the latest release's version ({}); nothing to do \
             (releases are compared by version, not by commit)",
            release.tag
        ));
        return Ok(0);
    }
    if release.version < current {
        ui::note(&format!(
            "{running} is newer than the latest release ({}); nothing to do",
            release.tag
        ));
        return Ok(0);
    }
    let asset = format!("tog-{}.tar.gz", platform.triple());
    let checksum = format!("{asset}.sha256");
    let (Some(asset_url), Some(checksum_url)) = (release.asset(&asset), release.asset(&checksum))
    else {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "release {} has no {asset} and {checksum} for this machine; releases: {RELEASES_PAGE}",
                release.tag
            ),
        ));
    };

    // Refuse before downloading when the rename at the end cannot happen.
    let (stage, mut stage_file) = Stage::create(&target)?;
    let installed = (|| -> io::Result<()> {
        let scratch = Scratch::new()?;
        ui::note(&format!("downloading {} ({asset})", release.tag));
        let expected = parse_sha256(
            &fetch::fetch_text_within(checksum_url, Some(LOOKUP_TIMEOUT))?,
            &asset,
        )?;
        let archive_path = scratch.0.join(&asset);
        fetch::download_file(asset_url, &archive_path, &expected)?;
        archive::extract_with_options(
            &archive_path,
            &scratch.0,
            &archive::ExtractOptions::platform_build(0),
            Compression::Gzip,
        )?;
        let binary = scratch.0.join("tog");
        if !binary.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{asset} did not contain a 'tog' binary"),
            ));
        }
        // Written through the handle `create_new` opened, so the bytes go
        // to the file that was created and to nothing a later rename of
        // the name could point at; synced so the rename below publishes
        // a complete file even across a power cut.
        let mut source = fs::File::open(&binary)?;
        io::copy(&mut source, &mut stage_file).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("write {}: {error}", stage.path.display()),
            )
        })?;
        stage_file.sync_all()?;
        // The handle must be closed before the file is executed: Linux
        // refuses to run a file that is open for writing.
        drop(source);
        Ok(())
    })()
    .and_then(|()| {
        drop(stage_file);
        smoke_test(&stage.path, release.version)
    })?;
    // Rename over the running binary: the process keeps its open inode,
    // and no moment exists where the path holds a half-written file.
    fs::rename(&stage.path, &target).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("cannot replace {}: {error}", target.display()),
        )
    })?;
    stage.consumed();
    // Best effort: make the directory entry durable too.
    if let Some(dir) = target.parent() {
        if let Ok(dir) = fs::File::open(dir) {
            let _ = dir.sync_all();
        }
    }
    ui::note(&format!(
        "updated {running} -> {installed} at {}",
        target.display()
    ));
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_parse_and_order() {
        assert_eq!(Version::parse("v0.2.0"), Some(Version(0, 2, 0)));
        assert_eq!(Version::parse("1.10.3"), Some(Version(1, 10, 3)));
        assert!(Version::parse("v0.2.0-rc1").is_none());
        assert!(Version::parse("v0.2").is_none());
        assert!(Version::parse("0.2.0.1").is_none());
        assert!(Version::parse("latest").is_none());
        assert!(Version::parse("v0.10.0") > Version::parse("v0.9.9"));
        assert_eq!(Version::running().unwrap().to_string(), cli::VERSION);
    }

    /// A 404 on the manifest names the URL and says no release is there;
    /// it never repeats the package-download explanation. Every other
    /// failure passes through.
    #[test]
    fn a_missing_manifest_says_no_release_is_published() {
        let url = "https://example.invalid/releases/latest";
        let error = no_release_found(url, fetch::status_failure(404));
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        assert_eq!(
            error.to_string(),
            format!("no published release at {url}; the server answered 404")
        );
        let throttled = fetch::status_failure(429);
        let text = throttled.to_string();
        assert_eq!(no_release_found(url, throttled).to_string(), text);
        assert_eq!(
            no_release_found(url, io::Error::other("offline")).to_string(),
            "offline"
        );
    }

    #[test]
    fn manifest_reads_tag_and_assets() {
        let release = Release::parse(
            r#"{"tag_name": "v0.2.0", "assets": [
                {"name": "tog-x86_64-unknown-linux-gnu.tar.gz", "browser_download_url": "https://example/a"},
                {"name": "tog-x86_64-unknown-linux-gnu.tar.gz.sha256", "browser_download_url": "https://example/b"},
                {"name": "notes.txt"}
            ]}"#,
        )
        .unwrap();
        assert_eq!(release.tag, "v0.2.0");
        assert_eq!(release.version, Version(0, 2, 0));
        assert_eq!(
            release.asset("tog-x86_64-unknown-linux-gnu.tar.gz.sha256"),
            Some("https://example/b")
        );
        assert_eq!(release.asset("notes.txt"), None);
        assert!(Release::parse("{}")
            .unwrap_err()
            .to_string()
            .contains("no tag_name"));
        assert!(Release::parse(r#"{"tag_name": "nightly"}"#)
            .unwrap_err()
            .to_string()
            .contains("not a version"));
        assert!(Release::parse("<html>")
            .unwrap_err()
            .to_string()
            .contains("not JSON"));
    }

    #[test]
    fn checksum_file_first_token_only() {
        let hex = "a".repeat(64);
        assert_eq!(
            parse_sha256(&format!("{hex}  tog-x.tar.gz\n"), "x").unwrap(),
            hex
        );
        assert_eq!(parse_sha256(&format!("{hex}\r\n"), "x").unwrap(), hex);
        // Same rules as install.sh's `cut -d' ' -f1`: upper-case hex, a
        // tab, or leading whitespace is not a digest sha256sum wrote.
        assert!(parse_sha256(&hex.to_ascii_uppercase(), "x").is_err());
        assert!(parse_sha256(&format!(" {hex}"), "x").is_err());
        assert!(parse_sha256(&format!("{hex}\tfile"), "x").is_err());
        assert!(parse_sha256("", "x").is_err());
        assert!(parse_sha256("deadbeef", "x").is_err());
    }
}

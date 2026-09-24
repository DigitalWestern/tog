//! The official Rust channel manifest (kernel provider layer): the
//! `channel-rust-<version>.toml` the Rust project publishes beside every
//! release, read as the data optional components and cross targets are
//! provisioned from.
//!
//! One manifest lists every package a release publishes (`pkg.<name>`), per
//! target triple (`target.<triple>`, or `target."*"` for a package that is
//! the same everywhere, like `rust-src`), with the archive URL and sha256
//! of each and an `available` flag for the rows a release names but did not
//! build. `renames` maps the names a toolchain file may use (`clippy`,
//! `rust-analyzer`) to the package names the manifest keys by
//! (`clippy-preview`, `rust-analyzer-preview`). Nothing here is hard-coded
//! per component: a name is looked up through `renames` and then `pkg`, and
//! whatever the release does not publish for the host is refused by name.
//!
//! This module only parses and looks up. The manifest's own bytes are
//! pinned by sha256 in the shipped catalog (`rust::CHANNEL_MANIFESTS`) and
//! verified on download, so every URL and digest read from it is as pinned
//! as a catalog row.

use crate::kernel::archive::Compression;
use crate::kernel::digest::Digest;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::io;

/// Where the Rust project publishes release archives and manifests.
pub const DIST: &str = "https://static.rust-lang.org/dist";

/// The manifest URL for one exact release.
pub fn manifest_url(version: &str) -> String {
    format!("{DIST}/channel-rust-{version}.toml")
}

/// The target key of a package that is the same on every host.
pub const ANY_TARGET: &str = "*";

/// The package that carries one target's standard library.
pub const STD_PACKAGE: &str = "rust-std";

#[derive(Debug, Deserialize)]
struct ManifestToml {
    #[serde(rename = "manifest-version")]
    manifest_version: String,
    #[serde(default)]
    pkg: BTreeMap<String, PackageToml>,
    #[serde(default)]
    renames: BTreeMap<String, RenameToml>,
    #[serde(default)]
    profiles: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct PackageToml {
    #[serde(default)]
    target: BTreeMap<String, TargetToml>,
}

#[derive(Debug, Deserialize)]
struct TargetToml {
    available: bool,
    url: Option<String>,
    hash: Option<String>,
    xz_url: Option<String>,
    xz_hash: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RenameToml {
    to: String,
}

/// One archive the manifest publishes: which package for which target,
/// where it is, and the bytes it must hash to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Archive {
    /// The manifest package name, after renames (`clippy-preview`).
    pub package: String,
    /// The target key the row was found under: a triple, or `*`.
    pub target: String,
    pub url: String,
    pub digest: Digest,
    pub compression: Compression,
}

/// A parsed channel manifest for one release.
#[derive(Debug)]
pub struct ChannelManifest {
    version: String,
    packages: BTreeMap<String, PackageToml>,
    renames: BTreeMap<String, String>,
    profiles: BTreeMap<String, Vec<String>>,
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

impl ChannelManifest {
    /// Parse the manifest of Rust `version`. Only manifest version 2 is
    /// understood; another one is refused rather than read by guess.
    pub fn parse(version: &str, text: &str) -> io::Result<ChannelManifest> {
        let parsed: ManifestToml = toml::from_str(text).map_err(|error| {
            invalid(format!(
                "channel manifest for Rust {version}: {}",
                error.to_string().trim()
            ))
        })?;
        if parsed.manifest_version != "2" {
            return Err(invalid(format!(
                "channel manifest for Rust {version} is manifest-version {}; this tog reads version 2",
                parsed.manifest_version
            )));
        }
        Ok(ChannelManifest {
            version: version.to_string(),
            packages: parsed.pkg,
            renames: parsed
                .renames
                .into_iter()
                .map(|(from, rename)| (from, rename.to))
                .collect(),
            profiles: parsed.profiles,
        })
    }

    /// The Rust release this manifest describes.
    pub fn version(&self) -> &str {
        &self.version
    }

    /// The package a toolchain-file name means: its `renames` target, or
    /// the name itself.
    pub fn package_name<'a>(&'a self, name: &'a str) -> &'a str {
        self.renames.get(name).map_or(name, String::as_str)
    }

    /// The archive of component `name` for `host`: the host's own row, or
    /// the target-independent `*` row. A name the release does not publish,
    /// publishes for other hosts only, or marks unavailable is refused by
    /// name.
    pub fn component(&self, name: &str, host: &str) -> io::Result<Archive> {
        let package = self.package_name(name);
        let spelled = if package == name {
            name.to_string()
        } else {
            format!("{name} ({package})")
        };
        let entry = self.packages.get(package).ok_or_else(|| {
            invalid(format!(
                "Rust {} does not publish a component named {spelled}",
                self.version
            ))
        })?;
        let (target, row) = entry
            .target
            .get_key_value(host)
            .or_else(|| entry.target.get_key_value(ANY_TARGET))
            .ok_or_else(|| {
                invalid(format!(
                    "Rust {} does not publish component {spelled} for {host}",
                    self.version
                ))
            })?;
        self.archive(package, target, row, &format!("component {spelled}"), host)
    }

    /// The packages profile `name` installs, as the manifest lists them for
    /// every host at once. A profile the manifest does not define is refused.
    pub fn profile(&self, name: &str) -> io::Result<&[String]> {
        self.profiles.get(name).map(Vec::as_slice).ok_or_else(|| {
            invalid(format!(
                "Rust {} does not define a profile named {name}",
                self.version
            ))
        })
    }

    /// Whether `package` is published, and available, for `host` (its own
    /// row or the `*` row). rustup installs a profile's packages that pass
    /// this and skips the rest: `rust-mingw` is in every profile and exists
    /// only for Windows hosts.
    pub fn publishes(&self, package: &str, host: &str) -> bool {
        self.packages.get(package).is_some_and(|entry| {
            entry
                .target
                .get(host)
                .or_else(|| entry.target.get(ANY_TARGET))
                .is_some_and(|row| row.available)
        })
    }

    /// The standard library for cross target `triple`.
    pub fn target_std(&self, triple: &str) -> io::Result<Archive> {
        let row = self
            .packages
            .get(STD_PACKAGE)
            .and_then(|entry| entry.target.get(triple))
            .ok_or_else(|| {
                invalid(format!(
                    "Rust {} does not publish a standard library for target {triple}",
                    self.version
                ))
            })?;
        self.archive(
            STD_PACKAGE,
            triple,
            row,
            &format!("target {triple}"),
            triple,
        )
    }

    fn archive(
        &self,
        package: &str,
        target: &str,
        row: &TargetToml,
        what: &str,
        host: &str,
    ) -> io::Result<Archive> {
        if !row.available {
            return Err(invalid(format!(
                "Rust {} does not publish {what} for {host}: its channel manifest marks it unavailable",
                self.version
            )));
        }
        let (url, hash, compression) = match (&row.xz_url, &row.xz_hash, &row.url, &row.hash) {
            (Some(url), Some(hash), _, _) => (url, hash, Compression::Xz),
            (_, _, Some(url), Some(hash)) => (url, hash, Compression::Gzip),
            _ => {
                return Err(invalid(format!(
                    "channel manifest for Rust {}: {package} for {target} is available but names no archive",
                    self.version
                )))
            }
        };
        if !url.starts_with(&format!("{DIST}/")) {
            return Err(invalid(format!(
                "channel manifest for Rust {}: {package} for {target} is served from {url}, outside {DIST}",
                self.version
            )));
        }
        Ok(Archive {
            package: package.to_string(),
            target: target.to_string(),
            url: url.clone(),
            digest: Digest::sha256(hash).map_err(|error| {
                invalid(format!(
                    "channel manifest for Rust {}: {package} for {target}: {error}",
                    self.version
                ))
            })?,
            compression,
        })
    }
}

#[cfg(test)]
pub(crate) const FIXTURE: &str = include_str!("rust_channel_fixture.toml");

#[cfg(test)]
mod tests {
    use super::*;

    const LINUX: &str = "x86_64-unknown-linux-gnu";
    const DARWIN: &str = "aarch64-apple-darwin";

    fn manifest() -> ChannelManifest {
        ChannelManifest::parse("1.96.1", FIXTURE).unwrap()
    }

    #[test]
    fn components_resolve_through_renames_to_their_host_row() {
        let manifest = manifest();
        let clippy = manifest.component("clippy", LINUX).unwrap();
        assert_eq!(clippy.package, "clippy-preview");
        assert_eq!(clippy.target, LINUX);
        assert_eq!(
            clippy.url,
            "https://static.rust-lang.org/dist/2026-06-30/clippy-1.96.1-x86_64-unknown-linux-gnu.tar.xz"
        );
        assert_eq!(
            clippy.digest.hex(),
            "385644867534c30c490f4507d61485a799f81dfaec7e2a91290a41bf43d8286a"
        );
        assert_eq!(clippy.compression, Compression::Xz);
        // The manifest's own package name is accepted as written.
        assert_eq!(manifest.component("clippy-preview", LINUX).unwrap(), clippy);
        let analyzer = manifest.component("rust-analyzer", DARWIN).unwrap();
        assert_eq!(analyzer.package, "rust-analyzer-preview");
        assert_eq!(analyzer.target, DARWIN);
        assert_eq!(
            manifest.component("rust-analyzer-preview", DARWIN).unwrap(),
            analyzer
        );
        assert_eq!(
            manifest.component("llvm-tools", LINUX).unwrap().package,
            "llvm-tools-preview"
        );
        assert_eq!(
            manifest.component("rust-docs", DARWIN).unwrap().package,
            "rust-docs"
        );
    }

    #[test]
    fn a_target_independent_component_uses_the_star_row() {
        let src = manifest().component("rust-src", LINUX).unwrap();
        assert_eq!(src.package, "rust-src");
        assert_eq!(src.target, ANY_TARGET);
        assert_eq!(
            src.url,
            "https://static.rust-lang.org/dist/2026-06-30/rust-src-1.96.1.tar.xz"
        );
        assert_eq!(
            manifest().component("rust-src", DARWIN).unwrap(),
            src,
            "the same archive on every host"
        );
    }

    #[test]
    fn cross_targets_are_the_rust_std_rows() {
        let wasm = manifest().target_std("wasm32-unknown-unknown").unwrap();
        assert_eq!(wasm.package, "rust-std");
        assert_eq!(wasm.target, "wasm32-unknown-unknown");
        assert!(wasm
            .url
            .ends_with("rust-std-1.96.1-wasm32-unknown-unknown.tar.xz"));
    }

    #[test]
    fn what_the_release_does_not_publish_is_refused_by_name() {
        let manifest = manifest();
        let error = manifest.component("no-such-tool", LINUX).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("Rust 1.96.1 does not publish a component named no-such-tool"),
            "{error}"
        );
        // Published, but only for another host.
        let error = manifest.component("rust-mingw", LINUX).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("does not publish component rust-mingw for x86_64-unknown-linux-gnu"),
            "{error}"
        );
        // Named by the release, marked `available = false`.
        let error = manifest.component("miri", LINUX).unwrap_err();
        assert!(error.to_string().contains("miri (miri-preview)"), "{error}");
        assert!(
            error.to_string().contains("marks it unavailable"),
            "{error}"
        );
        let error = manifest.target_std("riscv99-unknown-none").unwrap_err();
        assert!(
            error
                .to_string()
                .contains("does not publish a standard library for target riscv99-unknown-none"),
            "{error}"
        );
    }

    #[test]
    fn a_manifest_this_tog_cannot_read_is_refused() {
        let error = ChannelManifest::parse("1.96.1", "manifest-version = \"3\"\n").unwrap_err();
        assert!(error.to_string().contains("manifest-version 3"), "{error}");
        let error = ChannelManifest::parse("1.96.1", "not toml [").unwrap_err();
        assert!(
            error
                .to_string()
                .contains("channel manifest for Rust 1.96.1"),
            "{error}"
        );
        // A row whose archive lives outside the dist host is refused.
        let text = "manifest-version = \"2\"\n[pkg.x.target.\"*\"]\navailable = true\n\
                    xz_url = \"https://example.org/x.tar.xz\"\nxz_hash = \"{}\"\n"
            .replace("{}", &"a".repeat(64));
        let error = ChannelManifest::parse("1.96.1", &text)
            .unwrap()
            .component("x", LINUX)
            .unwrap_err();
        assert!(error.to_string().contains("outside"), "{error}");
        // A gzip-only row is read with its own compression.
        let text = "manifest-version = \"2\"\n[pkg.x.target.\"*\"]\navailable = true\n\
                    url = \"https://static.rust-lang.org/dist/x.tar.gz\"\nhash = \"{}\"\n"
            .replace("{}", &"b".repeat(64));
        let archive = ChannelManifest::parse("1.96.1", &text)
            .unwrap()
            .component("x", LINUX)
            .unwrap();
        assert_eq!(archive.compression, Compression::Gzip);
    }
}

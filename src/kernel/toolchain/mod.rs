//! Toolchain catalog (kernel layer): the shipped per-tailor pin tables as
//! release bundles, and the selection that a toolchain lock is minted from.
//!
//! A tailor turns its pin rows into [`Bundle`]s and hands them to
//! [`Catalog::new`]; nothing here names an ecosystem. `select` chooses a
//! bundle from the releases that are complete on every supported platform,
//! `source` is the typed endpoint policy retrieval will check, and `legacy`
//! seeds a selection from a closure written before the lock existed.
//! Realization still reads the pin tables directly: a catalog row carries the
//! same URL and digest, it does not mint a new object identity.

pub mod legacy;
pub mod select;
pub mod source;

pub use legacy::{seed, LegacyEvidence, ProvedArtifact};
pub use select::{Op, Request, Specifier, Version, VersionRequest};
pub use source::{CredentialRef, Endpoint, Publisher, SourcePolicy};

use crate::kernel::digest::Digest;
use crate::kernel::platform::Platform;
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io;

/// The canonical `<algorithm>:<hex>` spelling a catalog row, a bundle id and
/// a lock row share, so the row names the algorithm the verifier must use.
pub fn qualified(digest: &Digest) -> String {
    format!("{}:{}", digest.algo(), digest.hex())
}

/// One component of a release bundle: a fetched artifact (`embedded_in`
/// absent) or something shipped inside another component's artifact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Component {
    pub name: String,
    pub version: String,
    pub embedded_in: Option<String>,
}

impl Component {
    pub fn new(name: &str, version: &str) -> Component {
        Component {
            name: name.into(),
            version: version.into(),
            embedded_in: None,
        }
    }

    pub fn embedded(name: &str, version: &str, parent: &str) -> Component {
        Component {
            name: name.into(),
            version: version.into(),
            embedded_in: Some(parent.into()),
        }
    }
}

/// One platform's artifact for one independently fetched component: the
/// bytes (`url`, `digest`), who published them (`provider`, `build`) and
/// how they are laid out (`recipe`, an append-only id). Never a credential.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArtifactRow {
    pub platform: Platform,
    pub component: String,
    pub provider: String,
    pub build: String,
    pub recipe: String,
    pub url: String,
    pub digest: Digest,
}

impl ArtifactRow {
    pub fn new(
        platform: Platform,
        component: &str,
        provider: &str,
        build: &str,
        recipe: &str,
        url: &str,
        digest: Digest,
    ) -> ArtifactRow {
        ArtifactRow {
            platform,
            component: component.into(),
            provider: provider.into(),
            build: build.into(),
            recipe: recipe.into(),
            url: url.into(),
            digest,
        }
    }
}

/// A complete release of one ecosystem's toolchain: the catalog unit a lock
/// copies. `release` is an opaque unique key (provenance, never a selector);
/// `primary` names the component(s) whose version requests and ordering
/// use, in comparison order (BEAM is `["otp", "elixir"]`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bundle {
    pub release: String,
    pub revision: Option<u32>,
    pub primary: Vec<String>,
    pub components: Vec<Component>,
    pub artifacts: Vec<ArtifactRow>,
}

impl Bundle {
    pub fn component(&self, name: &str) -> Option<&Component> {
        self.components.iter().find(|c| c.name == name)
    }

    pub fn artifact(&self, platform: Platform, component: &str) -> Option<&ArtifactRow> {
        self.artifacts
            .iter()
            .find(|row| row.platform == platform && row.component == component)
    }

    /// The versions of the primary components, in `primary` order.
    pub fn primary_versions(&self) -> io::Result<Vec<Version>> {
        self.primary
            .iter()
            .map(|name| {
                let component = self.component(name).ok_or_else(|| {
                    invalid(format!(
                        "release {}: primary component {name} is not a component",
                        self.release
                    ))
                })?;
                Version::parse(&component.version).map_err(|error| {
                    invalid(format!(
                        "release {}: primary component {name} version {:?}: {error}",
                        self.release, component.version
                    ))
                })
            })
            .collect()
    }

    /// Is every independently fetched component present for `platform`?
    pub fn complete_for(&self, platform: Platform) -> bool {
        self.components
            .iter()
            .filter(|c| c.embedded_in.is_none())
            .all(|c| self.artifact(platform, &c.name).is_some())
    }

    /// Complete on every supported platform: the only releases selection
    /// considers, so the host never influences which bundle is chosen.
    pub fn complete_everywhere(&self) -> bool {
        Platform::ALL.iter().all(|p| self.complete_for(*p))
    }

    /// The canonical serialization the bundle id hashes: length-prefixed
    /// fields, one version record, then components sorted by name and
    /// artifact rows sorted by triple then component. `release`, `revision`
    /// and the ecosystem name stay out, so two catalogs minting the same
    /// bytes agree on the id.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let mut record = |fields: &[&str]| {
            for field in fields {
                out.extend_from_slice(field.len().to_string().as_bytes());
                out.push(b':');
                out.extend_from_slice(field.as_bytes());
            }
        };
        record(&["bundle", "1"]);
        let mut components: Vec<&Component> = self.components.iter().collect();
        components.sort_by(|a, b| a.name.cmp(&b.name));
        for c in components {
            record(&[
                "component",
                &c.name,
                &c.version,
                c.embedded_in.as_deref().unwrap_or(""),
            ]);
        }
        let mut artifacts: Vec<&ArtifactRow> = self.artifacts.iter().collect();
        artifacts.sort_by(|a, b| {
            (a.platform.triple(), &a.component).cmp(&(b.platform.triple(), &b.component))
        });
        for row in artifacts {
            record(&[
                "artifact",
                row.platform.triple(),
                &row.component,
                &row.provider,
                &row.build,
                &row.recipe,
                &row.url,
                &qualified(&row.digest),
            ]);
        }
        out
    }

    /// `sha256:<hex>` over [`Bundle::canonical_bytes`].
    pub fn bundle_id(&self) -> String {
        format!(
            "sha256:{}",
            hex::encode(Sha256::digest(self.canonical_bytes()))
        )
    }

    /// Structural checks a single bundle can do alone.
    fn validate(&self) -> io::Result<()> {
        let release = &self.release;
        let bad = |what: String| invalid(format!("release {release}: {what}"));
        if release.is_empty() {
            return Err(invalid("release key is empty"));
        }
        if self.primary.is_empty() {
            return Err(bad("no primary component".into()));
        }
        let mut names = BTreeSet::new();
        for c in &self.components {
            if c.name.is_empty() || c.version.is_empty() {
                return Err(bad(format!(
                    "component {:?} lacks a name or version",
                    c.name
                )));
            }
            if !names.insert(c.name.as_str()) {
                return Err(bad(format!("duplicate component {}", c.name)));
            }
        }
        for c in &self.components {
            // Follow the embedding chain to an independently fetched
            // ancestor; a missing parent or a cycle has no digest to cover it.
            let mut seen = BTreeSet::from([c.name.as_str()]);
            let mut current = c;
            while let Some(parent) = current.embedded_in.as_deref() {
                if !seen.insert(parent) {
                    return Err(bad(format!("component {} is embedded in a cycle", c.name)));
                }
                current = self.component(parent).ok_or_else(|| {
                    bad(format!(
                        "component {} is embedded in unknown {parent}",
                        c.name
                    ))
                })?;
            }
        }
        self.primary_versions()?;
        let mut rows = BTreeSet::new();
        for row in &self.artifacts {
            let component = self.component(&row.component).ok_or_else(|| {
                bad(format!(
                    "artifact row for unknown component {}",
                    row.component
                ))
            })?;
            if component.embedded_in.is_some() {
                return Err(bad(format!(
                    "embedded component {} has its own artifact row",
                    row.component
                )));
            }
            if row.provider.is_empty()
                || row.build.is_empty()
                || row.recipe.is_empty()
                || row.url.is_empty()
            {
                return Err(bad(format!(
                    "artifact row {}/{} lacks provider, build, recipe or url",
                    row.platform.triple(),
                    row.component
                )));
            }
            if !rows.insert((row.platform.triple(), row.component.as_str())) {
                return Err(bad(format!(
                    "duplicate artifact row {}/{}",
                    row.platform.triple(),
                    row.component
                )));
            }
        }
        Ok(())
    }
}

/// One ecosystem's validated release bundles, in catalog (append) order.
#[derive(Clone, Debug)]
pub struct Catalog {
    ecosystem: String,
    bundles: Vec<Bundle>,
}

impl Catalog {
    /// Validate the bundles: unique release keys and bundle ids, resolvable
    /// embedding chains, numeric primary versions, one artifact row per
    /// platform and component. Duplicates are catalog errors, never
    /// tie-breaks.
    pub fn new(ecosystem: &str, bundles: Vec<Bundle>) -> io::Result<Catalog> {
        if ecosystem.is_empty() {
            return Err(invalid("catalog ecosystem is empty"));
        }
        let mut releases = BTreeSet::new();
        let mut ids: BTreeMap<String, &str> = BTreeMap::new();
        for bundle in &bundles {
            bundle
                .validate()
                .map_err(|error| invalid(format!("{ecosystem} catalog: {error}")))?;
            if !releases.insert(bundle.release.as_str()) {
                return Err(invalid(format!(
                    "{ecosystem} catalog: duplicate release key {}",
                    bundle.release
                )));
            }
            if let Some(other) = ids.insert(bundle.bundle_id(), &bundle.release) {
                return Err(invalid(format!(
                    "{ecosystem} catalog: releases {other} and {} are the same bundle",
                    bundle.release
                )));
            }
        }
        Ok(Catalog {
            ecosystem: ecosystem.into(),
            bundles,
        })
    }

    pub fn ecosystem(&self) -> &str {
        &self.ecosystem
    }

    pub fn bundles(&self) -> &[Bundle] {
        &self.bundles
    }

    pub fn release(&self, key: &str) -> Option<&Bundle> {
        self.bundles.iter().find(|b| b.release == key)
    }

    /// The releases complete on every supported platform, in catalog order.
    pub fn complete(&self) -> impl Iterator<Item = &Bundle> {
        self.bundles.iter().filter(|b| b.complete_everywhere())
    }
}

pub(crate) fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
pub(crate) mod fixtures {
    use super::*;

    pub fn sha256(fill: char) -> Digest {
        Digest::sha256(&fill.to_string().repeat(64)).unwrap()
    }

    pub fn sha512(fill: char) -> Digest {
        Digest::sha512(&fill.to_string().repeat(128)).unwrap()
    }

    pub fn row(platform: Platform, component: &str, fill: char) -> ArtifactRow {
        ArtifactRow::new(
            platform,
            component,
            "example.org",
            "build",
            "example/1",
            &format!("https://example.org/{}/{component}", platform.triple()),
            sha256(fill),
        )
    }

    /// A single-component bundle with one row per listed platform.
    pub fn bundle(release: &str, component: &str, version: &str, platforms: &[Platform]) -> Bundle {
        Bundle {
            release: release.into(),
            revision: None,
            primary: vec![component.into()],
            components: vec![Component::new(component, version)],
            artifacts: platforms
                .iter()
                .map(|p| row(*p, component, if p.is_macos() { 'a' } else { 'b' }))
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::*;
    use super::*;

    const DARWIN: Platform = Platform::Aarch64AppleDarwin;
    const LINUX: Platform = Platform::X86_64UnknownLinuxGnu;

    #[test]
    fn complete_means_every_fetched_component_on_every_platform() {
        let both = bundle("r1", "node", "1.0.0", Platform::ALL);
        assert!(both.complete_everywhere());
        let darwin_only = bundle("r2", "node", "1.0.0", &[DARWIN]);
        assert!(darwin_only.complete_for(DARWIN));
        assert!(!darwin_only.complete_for(LINUX));
        assert!(!darwin_only.complete_everywhere());
        // An embedded component needs no row of its own.
        let mut embedded = both.clone();
        embedded
            .components
            .push(Component::embedded("npm", "11.0.0", "node"));
        assert!(embedded.complete_everywhere());
        // A second fetched component with one row is incomplete.
        let mut half = both.clone();
        half.components.push(Component::new("uv", "0.1.0"));
        half.artifacts.push(row(LINUX, "uv", 'c'));
        assert!(half.complete_for(LINUX));
        assert!(!half.complete_for(DARWIN));
    }

    #[test]
    fn catalog_rejects_duplicate_release_keys_and_identical_bundles() {
        let a = bundle("r1", "node", "1.0.0", Platform::ALL);
        let mut same_key = bundle("r1", "node", "2.0.0", Platform::ALL);
        let error = Catalog::new("node", vec![a.clone(), same_key.clone()]).unwrap_err();
        assert!(
            error.to_string().contains("duplicate release key r1"),
            "{error}"
        );
        same_key.release = "r2".into();
        same_key.components[0].version = "1.0.0".into();
        let error = Catalog::new("node", vec![a, same_key]).unwrap_err();
        assert!(error.to_string().contains("same bundle"), "{error}");
    }

    #[test]
    fn catalog_rejects_broken_embedding_and_stray_rows() {
        let mut orphan = bundle("r1", "node", "1.0.0", Platform::ALL);
        orphan
            .components
            .push(Component::embedded("npm", "11.0.0", "nope"));
        let error = Catalog::new("node", vec![orphan]).unwrap_err();
        assert!(
            error.to_string().contains("embedded in unknown nope"),
            "{error}"
        );

        let mut cycle = bundle("r1", "node", "1.0.0", Platform::ALL);
        cycle.components.push(Component::embedded("a", "1", "b"));
        cycle.components.push(Component::embedded("b", "1", "a"));
        let error = Catalog::new("node", vec![cycle]).unwrap_err();
        assert!(error.to_string().contains("cycle"), "{error}");

        let mut embedded_row = bundle("r1", "node", "1.0.0", Platform::ALL);
        embedded_row
            .components
            .push(Component::embedded("npm", "11.0.0", "node"));
        embedded_row.artifacts.push(row(LINUX, "npm", 'c'));
        let error = Catalog::new("node", vec![embedded_row]).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("embedded component npm has its own artifact row"),
            "{error}"
        );

        let mut unknown_row = bundle("r1", "node", "1.0.0", Platform::ALL);
        unknown_row.artifacts.push(row(LINUX, "ghost", 'c'));
        let error = Catalog::new("node", vec![unknown_row]).unwrap_err();
        assert!(
            error.to_string().contains("unknown component ghost"),
            "{error}"
        );

        let mut twice = bundle("r1", "node", "1.0.0", Platform::ALL);
        twice.artifacts.push(row(LINUX, "node", 'c'));
        let error = Catalog::new("node", vec![twice]).unwrap_err();
        assert!(
            error.to_string().contains("duplicate artifact row"),
            "{error}"
        );

        let mut bad_primary = bundle("r1", "node", "1.0.0", Platform::ALL);
        bad_primary.primary = vec!["ghost".into()];
        let error = Catalog::new("node", vec![bad_primary]).unwrap_err();
        assert!(
            error.to_string().contains("primary component ghost"),
            "{error}"
        );

        let mut bad_version = bundle("r1", "node", "v1", Platform::ALL);
        bad_version.components[0].version = "v1".into();
        let error = Catalog::new("node", vec![bad_version]).unwrap_err();
        assert!(error.to_string().contains("version \"v1\""), "{error}");
    }

    #[test]
    fn digests_carry_through_with_their_algorithm() {
        let mut b = bundle("r1", "sdk", "9.0.0", &[DARWIN]);
        let mut linux = row(LINUX, "sdk", 'b');
        linux.digest = sha512('f');
        b.artifacts.push(linux);
        let catalog = Catalog::new("dotnet", vec![b]).unwrap();
        let bundle = &catalog.bundles()[0];
        assert_eq!(
            qualified(&bundle.artifact(DARWIN, "sdk").unwrap().digest),
            format!("sha256:{}", "a".repeat(64))
        );
        assert_eq!(
            qualified(&bundle.artifact(LINUX, "sdk").unwrap().digest),
            format!("sha512:{}", "f".repeat(128))
        );
        // The bundle id names the algorithm too, so re-pinning to another
        // algorithm is a different bundle.
        let mut repinned = catalog.bundles()[0].clone();
        repinned.artifacts[1].digest = sha256('f');
        assert_ne!(repinned.bundle_id(), bundle.bundle_id());
    }

    #[test]
    fn bundle_id_is_order_independent_and_excludes_release_and_revision() {
        let mut a = bundle("r1", "node", "1.0.0", Platform::ALL);
        a.components
            .push(Component::embedded("npm", "11.0.0", "node"));
        let mut b = a.clone();
        b.release = "other".into();
        b.revision = Some(7);
        b.components.reverse();
        b.artifacts.reverse();
        assert_eq!(a.bundle_id(), b.bundle_id());
        let mut c = a.clone();
        c.artifacts[0].recipe = "example/2".into();
        assert_ne!(a.bundle_id(), c.bundle_id());
        let text = String::from_utf8(a.canonical_bytes()).unwrap();
        assert!(text.starts_with("6:bundle1:19:component"), "{text}");
        assert!(
            text.contains("8:artifact20:aarch64-apple-darwin4:node"),
            "{text}"
        );
    }

    #[test]
    fn bundle_id_matches_the_design_example() {
        // The Node bundle written out in docs/agent/DESIGNS.md §1.
        let bundle = Bundle {
            release: "node-24.20.0-r1".into(),
            revision: Some(1),
            primary: vec!["node".into()],
            components: vec![
                Component::new("node", "24.20.0"),
                Component::embedded("bundled-npm", "11.19.0", "node"),
                Component::embedded("node-gyp", "12.4.0", "bundled-npm"),
            ],
            artifacts: vec![
                ArtifactRow::new(
                    DARWIN,
                    "node",
                    "nodejs.org",
                    "24.20.0",
                    "nodejs/legacy",
                    "https://nodejs.org/dist/v24.20.0/node-v24.20.0-darwin-arm64.tar.gz",
                    Digest::sha256(
                        "40e5607e5ecb3db9192723776da2d75d966260fc74a7a9e731c1bd67dda96bc8",
                    )
                    .unwrap(),
                ),
                ArtifactRow::new(
                    LINUX,
                    "node",
                    "nodejs.org",
                    "24.20.0",
                    "nodejs/legacy",
                    "https://nodejs.org/dist/v24.20.0/node-v24.20.0-linux-x64.tar.gz",
                    Digest::sha256(
                        "855d581f8a4eb1a8117e3426de25fe02770592febcfb31369aee1ffbfee9e8ec",
                    )
                    .unwrap(),
                ),
            ],
        };
        assert_eq!(
            bundle.bundle_id(),
            "sha256:683bc7a0c5d38d3fcc9e73a6e55ab75bda308fb66204c4808942e750b5c1266b"
        );
    }
}

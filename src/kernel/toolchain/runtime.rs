//! The selected toolchain, as every operation downstream of selection reads
//! it: one resolved bundle per ecosystem plus where it came from.
//!
//! Selection happens once, at lock creation or `tog update --toolchain`. A
//! [`Selected`] is the result carried through sync, run, build and `x`, so
//! nothing after this point reopens a catalog or re-decides a version.

#[cfg(test)]
use super::qualified;
use super::{invalid, Bundle, Catalog, Request};
use crate::kernel::digest::Digest;
use crate::kernel::platform::Platform;
use std::collections::BTreeMap;
use std::io;

/// Where a selection came from. It decides what may be written, not what is
/// used: a `Lock` selection is honored, a `Created` one is published.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// Read from the committed `tog-toolchain.toml`.
    Lock,
    /// Selected now for a project that has no lock; a lock is pending.
    Created,
    /// Re-selected by `tog update --toolchain`.
    Updated,
    /// The shipped default, for work with no project lock to honor.
    Shipped,
}

/// One ecosystem's resolved toolchain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Selected {
    /// The lock ecosystem name (`python`, `node`, `rust`, `go`, `ruby`,
    /// `elixir`, `dotnet`), which is the `[toolchain.<name>]` section key.
    pub ecosystem: String,
    pub bundle: Bundle,
    /// Hex sha256 of the lock bytes this came from; `None` when no lock is
    /// involved.
    pub lock_sha256: Option<String>,
    pub source: Source,
    /// The releases this ecosystem's lock section pins for its helpers, by
    /// helper lock ecosystem: `rust` for the Rust a Python project's sdists
    /// build with when the project does not lock Rust itself. Written when
    /// the section is, so a catalog whose default moves does not move a
    /// locked project's builds. Exactly the section's pins: empty for a
    /// section written before pins existed (the ecosystem's builds supply
    /// the release those sections used) and when no lock is involved.
    pub helpers: BTreeMap<String, String>,
}

/// One component's bytes on one platform: everything retrieval needs and
/// nothing it does not.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArtifactSpec {
    pub component: String,
    pub version: String,
    pub provider: String,
    pub build: String,
    pub recipe: String,
    pub url: String,
    pub digest: Digest,
}

impl ArtifactSpec {
    /// Refuse a row this tog cannot realize: a `recipe` it does not know, or
    /// a digest of another algorithm than `algo`, the one the publisher
    /// signs with. `ecosystem` names the selection in the message.
    pub fn check(&self, ecosystem: &str, recipe: &str, algo: &str) -> io::Result<()> {
        self.check_from(ecosystem, recipe, algo, "tog-toolchain.toml")
    }

    /// `check`, for a row read from `source` (where a refusal says the
    /// row came from) rather than the project's `tog-toolchain.toml`.
    pub fn check_from(
        &self,
        ecosystem: &str,
        recipe: &str,
        algo: &str,
        source: &str,
    ) -> io::Result<()> {
        if self.recipe != recipe {
            return Err(invalid(format!(
                "{ecosystem}: recipe {} in {source} is not known to this tog; upgrade tog",
                self.recipe
            )));
        }
        if self.digest.algo() != algo {
            return Err(invalid(format!(
                "{ecosystem}: {} artifact digest must be {algo}, got {}",
                self.component,
                self.digest.algo()
            )));
        }
        Ok(())
    }
}

impl Selected {
    /// Refuse a selection made for another ecosystem or runtime than the
    /// tailor about to realize it. That is a caller's mistake, so the error
    /// is `InvalidInput`, not the `InvalidData` of a bad lock row.
    pub fn require(&self, ecosystem: &str, runtime: &str) -> io::Result<()> {
        if self.ecosystem != ecosystem || self.runtime() != runtime {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "{ecosystem}: selected toolchain is {} ({}), not {ecosystem} ({runtime})",
                    self.ecosystem,
                    self.runtime()
                ),
            ));
        }
        Ok(())
    }

    /// [`Selected::artifact`], checked with [`ArtifactSpec::check`].
    pub fn checked_artifact(
        &self,
        platform: Platform,
        component: &str,
        recipe: &str,
        algo: &str,
    ) -> io::Result<ArtifactSpec> {
        let row = self.artifact(platform, component)?;
        row.check(&self.ecosystem, recipe, algo)?;
        Ok(row)
    }

    /// The row for one component on one platform, with the component's
    /// version beside it. An embedded component has no row of its own.
    pub fn artifact(&self, platform: Platform, component: &str) -> io::Result<ArtifactSpec> {
        let row = self.bundle.artifact(platform, component).ok_or_else(|| {
            invalid(format!(
                "{}: release {} has no {component} artifact for {}",
                self.ecosystem,
                self.bundle.release,
                platform.triple()
            ))
        })?;
        Ok(ArtifactSpec {
            component: component.to_string(),
            version: self.version(component)?.to_string(),
            provider: row.provider.clone(),
            build: row.build.clone(),
            recipe: row.recipe.clone(),
            url: row.url.clone(),
            digest: row.digest.clone(),
        })
    }

    /// One component's exact version.
    pub fn version(&self, component: &str) -> io::Result<&str> {
        self.bundle
            .component(component)
            .map(|entry| entry.version.as_str())
            .ok_or_else(|| {
                invalid(format!(
                    "{}: release {} has no component {component}",
                    self.ecosystem, self.bundle.release
                ))
            })
    }

    /// The id of this selection's lock section: the bundle's id, covering
    /// the helper pins when there are some ([`Bundle::section_id`]). It is
    /// what a closure records and `status` compares with the section.
    pub fn bundle_id(&self) -> String {
        self.bundle.section_id(&self.helpers)
    }

    /// The primary versions joined with `+`: one version for most
    /// ecosystems, `27.3.4+1.18.4` for the BEAM pair.
    pub fn primary_version(&self) -> String {
        self.bundle
            .primary
            .iter()
            .filter_map(|name| self.bundle.component(name))
            .map(|entry| entry.version.clone())
            .collect::<Vec<_>>()
            .join("+")
    }

    /// The component whose version names the runtime.
    pub fn runtime(&self) -> &str {
        self.bundle
            .primary
            .first()
            .map(String::as_str)
            .unwrap_or_default()
    }

    /// One line of narration: what was selected and which release it is.
    pub fn describe(&self) -> String {
        format!(
            "{} {} (release {})",
            self.runtime(),
            self.primary_version(),
            self.bundle.release
        )
    }

    #[cfg(test)]
    /// The algorithm-qualified digest of one component's bytes on one
    /// platform, the spelling a lock row and a bundle id share.
    pub fn qualified_digest(&self, platform: Platform, component: &str) -> io::Result<String> {
        Ok(qualified(&self.artifact(platform, component)?.digest))
    }
}

/// The shipped default: the release `catalog` names as its default (the
/// newest complete release when it names none), for work with no project
/// lock to honor.
pub fn shipped(catalog: &Catalog) -> io::Result<Selected> {
    let bundle = catalog.select(&Request::newest())?;
    Ok(Selected {
        helpers: Default::default(),
        ecosystem: catalog.ecosystem().to_string(),
        bundle: bundle.clone(),
        lock_sha256: None,
        source: Source::Shipped,
    })
}

#[cfg(test)]
mod tests {
    use super::super::fixtures::*;
    use super::super::{Catalog, Component};
    use super::*;

    const DARWIN: Platform = Platform::Aarch64AppleDarwin;
    const LINUX: Platform = Platform::X86_64UnknownLinuxGnu;

    #[test]
    fn a_refused_row_names_where_it_came_from() {
        let row = ArtifactSpec {
            component: "channel-manifest".into(),
            version: "1.0.0".into(),
            provider: "rust-lang".into(),
            build: "official".into(),
            recipe: "rust-channel-manifest/9".into(),
            url: "https://static.rust-lang.org/dist/channel-rust-1.0.0.toml".into(),
            digest: Digest::sha256(&"a".repeat(64)).unwrap(),
        };
        let error = row
            .check_from(
                "cargo",
                "rust-channel-manifest/1",
                "sha256",
                "this tog's shipped Rust catalog",
            )
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "cargo: recipe rust-channel-manifest/9 in this tog's shipped Rust catalog is not \
             known to this tog; upgrade tog"
        );
        let error = row
            .check("cargo", "rust-channel-manifest/1", "sha256")
            .unwrap_err();
        assert!(
            error.to_string().contains("in tog-toolchain.toml"),
            "{error}"
        );
    }

    #[test]
    fn a_selection_answers_versions_artifacts_and_narration() {
        let catalog = Catalog::new(
            "python",
            vec![
                bundle("cpython-3.12.14", "cpython", "3.12.14", Platform::ALL),
                bundle("cpython-3.13.15", "cpython", "3.13.15", Platform::ALL),
            ],
        )
        .unwrap();
        let selected = shipped(&catalog).unwrap();
        assert_eq!(selected.source, Source::Shipped);
        assert_eq!(selected.lock_sha256, None);
        assert_eq!(selected.runtime(), "cpython");
        assert_eq!(selected.version("cpython").unwrap(), "3.13.15");
        assert_eq!(selected.primary_version(), "3.13.15");
        assert_eq!(
            selected.describe(),
            "cpython 3.13.15 (release cpython-3.13.15)"
        );
        assert_eq!(selected.bundle_id(), selected.bundle.bundle_id());
        let row = selected.artifact(LINUX, "cpython").unwrap();
        assert_eq!(row.version, "3.13.15");
        assert_eq!(row.recipe, "example/1");
        assert!(row.url.contains("x86_64-unknown-linux-gnu"));
        assert_eq!(
            selected.qualified_digest(DARWIN, "cpython").unwrap(),
            format!("sha256:{}", "a".repeat(64))
        );
        // Both refusals name what was asked for.
        let error = selected.artifact(LINUX, "uv").unwrap_err().to_string();
        assert!(error.contains("uv"), "{error}");
        assert!(error.contains("x86_64-unknown-linux-gnu"), "{error}");
        let error = selected.version("uv").unwrap_err().to_string();
        assert!(error.contains("no component uv"), "{error}");
    }

    #[test]
    fn a_primary_pair_joins_its_versions() {
        let mut beam = bundle("beam-1", "otp", "27.3.4", Platform::ALL);
        beam.components.push(Component::new("elixir", "1.18.4"));
        beam.artifacts
            .extend(Platform::ALL.iter().map(|p| row(*p, "elixir", 'c')));
        beam.primary = vec!["otp".into(), "elixir".into()];
        let selected = Selected {
            helpers: Default::default(),
            ecosystem: "elixir".into(),
            bundle: beam,
            lock_sha256: Some("f".repeat(64)),
            source: Source::Lock,
        };
        assert_eq!(selected.primary_version(), "27.3.4+1.18.4");
        assert_eq!(selected.runtime(), "otp");
        assert_eq!(selected.describe(), "otp 27.3.4+1.18.4 (release beam-1)");
    }
}

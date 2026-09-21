//! The selected toolchain, as every operation downstream of selection reads
//! it: one resolved bundle per ecosystem plus where it came from.
//!
//! Selection happens once, at lock creation or `tog update --toolchain`. A
//! [`Selected`] is the result carried through sync, run, build and `x`, so
//! nothing after this point reopens a catalog or re-decides a version.

use super::{invalid, qualified, Bundle, Catalog, Request};
use crate::kernel::digest::Digest;
use crate::kernel::platform::Platform;
use std::io;

/// Where a selection came from. It decides what may be written, not what is
/// used: a `Lock` selection is honored, a `Created` one is published.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// Read from the committed `tog-toolchain.toml`.
    Lock,
    /// Selected now for a project that has no lock; a lock is pending.
    Created,
    /// Recovered from a closure written before the lock existed.
    Seeded,
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

impl Selected {
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

    pub fn bundle_id(&self) -> String {
        self.bundle.bundle_id()
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

    /// The algorithm-qualified digest of one component's bytes on one
    /// platform, the spelling a lock row and a bundle id share.
    pub fn qualified_digest(&self, platform: Platform, component: &str) -> io::Result<String> {
        Ok(qualified(&self.artifact(platform, component)?.digest))
    }

    /// What a closure records about the toolchain it was realized from: the
    /// release, its immutable id, and every component version in it. This is
    /// the `toolchain` body key every lock-aware tailor writes, and the one
    /// `commands::shared` tests for before it offers a closure as legacy
    /// evidence: a closure that carries it states its own selection, so
    /// nothing has to be recovered from the versions scattered through its
    /// plan.
    ///
    /// The record is a function of the selection alone. `source` and
    /// `lock_sha256` are deliberately outside it: the same toolchain read
    /// from a lock, seeded, or selected fresh must write the same bytes, or
    /// every comparison against a record would turn on how the run got
    /// there rather than on what it used.
    pub fn record(&self) -> serde_json::Value {
        let components: serde_json::Map<String, serde_json::Value> = self
            .bundle
            .components
            .iter()
            .map(|entry| {
                (
                    entry.name.clone(),
                    serde_json::Value::String(entry.version.clone()),
                )
            })
            .collect();
        serde_json::json!({
            "ecosystem": self.ecosystem,
            "release": self.bundle.release,
            "bundle_id": self.bundle_id(),
            "components": components,
        })
    }
}

/// The shipped default: the newest complete release in `catalog`, for work
/// with no project lock to honor.
pub fn shipped(catalog: &Catalog) -> io::Result<Selected> {
    let bundle = catalog.select(&Request::newest())?;
    Ok(Selected {
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
            ecosystem: "elixir".into(),
            bundle: beam,
            lock_sha256: Some("f".repeat(64)),
            source: Source::Lock,
        };
        assert_eq!(selected.primary_version(), "27.3.4+1.18.4");
        assert_eq!(selected.runtime(), "otp");
        assert_eq!(selected.describe(), "otp 27.3.4+1.18.4 (release beam-1)");
    }

    #[test]
    fn the_closure_record_names_the_release_and_every_component_version() {
        let catalog = Catalog::new(
            "go",
            vec![bundle("go-1.27.0", "go", "1.27.0", Platform::ALL)],
        )
        .unwrap();
        let selected = shipped(&catalog).unwrap();
        let record = selected.record();
        assert_eq!(record["ecosystem"], "go");
        assert_eq!(record["release"], "go-1.27.0");
        assert_eq!(record["bundle_id"], selected.bundle_id());
        assert_eq!(record["components"]["go"], "1.27.0");

        // The same selection records the same bytes however it was reached:
        // a record is about the toolchain, not about the run.
        let mut from_lock = selected.clone();
        from_lock.source = Source::Lock;
        from_lock.lock_sha256 = Some("c".repeat(64));
        assert_eq!(from_lock.record(), record);

        // Embedded components are versions too: they are what the closure
        // was built with, even though they have no artifact row.
        let mut with_embedded = selected;
        with_embedded
            .bundle
            .components
            .push(Component::embedded("stdlib", "1.27.0", "go"));
        assert_eq!(with_embedded.record()["components"]["stdlib"], "1.27.0");
    }
}

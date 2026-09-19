//! Legacy seeding: choosing the bundle a lock is first written from when a
//! project already has closures written before the lock existed.
//!
//! A seed comes only from what the closure proves: the platform it was
//! realized on and the exact primary version(s) it records, plus, when the
//! tailor can verify the closure's runtime object against its pins, the
//! artifact(s) that object was built from. Anything less refuses and names
//! `tog update --toolchain`; the seed never guesses from the shipped
//! default. A closure proves its own platform only: the other platform's
//! rows must come from a bundle the catalog already holds complete.

use super::{invalid, qualified, Bundle, Catalog, Version};
use crate::kernel::digest::Digest;
use crate::kernel::platform::Platform;
use std::io;

/// The next step every refusal names.
pub const UPDATE_HINT: &str = "run `tog update --toolchain`";

/// An artifact a closure's recorded runtime object proves it was built
/// from: the tailor recomputed the object id from a pin row and it matched.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProvedArtifact {
    pub component: String,
    pub recipe: String,
    pub digest: Digest,
}

/// What a pre-lock closure says about the toolchain it was realized with.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LegacyEvidence {
    /// The closure envelope's platform; closures written before that field
    /// existed have none, and no host value stands in for it.
    pub platform: Option<Platform>,
    /// Recorded component versions, primary components among them.
    pub versions: Vec<(String, String)>,
    /// Artifacts proved on `platform`, when the tailor could verify them.
    pub artifacts: Vec<ProvedArtifact>,
}

impl LegacyEvidence {
    pub fn version(&self, component: &str) -> Option<&str> {
        self.versions
            .iter()
            .find(|(name, _)| name == component)
            .map(|(_, version)| version.as_str())
    }
}

fn refuse(catalog: &Catalog, why: String) -> io::Error {
    invalid(format!(
        "cannot seed the {} toolchain lock from the existing closure: {why}; {UPDATE_HINT}",
        catalog.ecosystem()
    ))
}

/// The bundle `evidence` proves, or a refusal naming what is missing.
pub fn seed<'a>(catalog: &'a Catalog, evidence: &LegacyEvidence) -> io::Result<&'a Bundle> {
    let Some(platform) = evidence.platform else {
        return Err(refuse(catalog, "the closure records no platform".into()));
    };
    let Some(first) = catalog.bundles().first() else {
        return Err(invalid(format!(
            "{} catalog is empty: nothing to seed a toolchain lock from",
            catalog.ecosystem()
        )));
    };
    // `Catalog::new` checked that every bundle shares this primary list.
    let mut wanted = Vec::new();
    for name in &first.primary {
        let text = evidence
            .version(name)
            .ok_or_else(|| refuse(catalog, format!("the closure records no {name} version")))?;
        let version = Version::parse(text).map_err(|error| {
            refuse(
                catalog,
                format!("the closure's {name} version {text:?} is not exact: {error}"),
            )
        })?;
        wanted.push((name.as_str(), version));
    }
    let described: Vec<String> = wanted.iter().map(|(n, v)| format!("{n} {v}")).collect();
    let described = described.join(", ");

    let mut candidates = Vec::new();
    for bundle in catalog.bundles() {
        let versions = bundle.primary_versions()?;
        if versions
            .iter()
            .zip(&wanted)
            .all(|(have, (_, want))| have == want)
        {
            candidates.push(bundle);
        }
    }
    if candidates.is_empty() {
        return Err(refuse(
            catalog,
            format!("no catalog release has {described}"),
        ));
    }

    // Proved artifacts narrow the candidates: a bundle whose row on the
    // closure's platform disagrees on digest or recipe cannot be the one the
    // closure was realized from.
    for proof in &evidence.artifacts {
        candidates.retain(|bundle| {
            bundle
                .artifact(platform, &proof.component)
                .is_some_and(|row| row.digest == proof.digest && row.recipe == proof.recipe)
        });
        if candidates.is_empty() {
            return Err(refuse(
                catalog,
                format!(
                    "the closure's {} object was built from {} under recipe {} on {}, which no catalog release with {described} carries",
                    proof.component,
                    qualified(&proof.digest),
                    proof.recipe,
                    platform.triple()
                ),
            ));
        }
    }
    if candidates.len() > 1 {
        let keys: Vec<&str> = candidates.iter().map(|b| b.release.as_str()).collect();
        return Err(refuse(
            catalog,
            format!(
                "releases {} all have {described} and the closure proves no artifact that tells them apart",
                keys.join(", ")
            ),
        ));
    }
    let bundle = candidates[0];
    if !bundle.complete_for(platform) {
        return Err(refuse(
            catalog,
            format!(
                "release {} has no complete {} artifact set",
                bundle.release,
                platform.triple()
            ),
        ));
    }
    for other in Platform::ALL.iter().filter(|p| **p != platform) {
        if !bundle.complete_for(*other) {
            return Err(refuse(
                catalog,
                format!(
                    "release {} has no complete {} artifact set, and a closure realized on {} is not evidence for {}",
                    bundle.release,
                    other.triple(),
                    platform.triple(),
                    other.triple()
                ),
            ));
        }
    }
    Ok(bundle)
}

#[cfg(test)]
mod tests {
    use super::super::fixtures::*;
    use super::super::{Component, Request};
    use super::*;

    const DARWIN: Platform = Platform::Aarch64AppleDarwin;
    const LINUX: Platform = Platform::X86_64UnknownLinuxGnu;

    fn python_catalog() -> Catalog {
        Catalog::new(
            "python",
            vec![
                bundle("py312", "cpython", "3.12.14", Platform::ALL),
                bundle("py313", "cpython", "3.13.15", Platform::ALL),
                bundle("py311-darwin", "cpython", "3.11.16", &[DARWIN]),
            ],
        )
        .unwrap()
    }

    fn evidence(platform: Option<Platform>, version: &str) -> LegacyEvidence {
        LegacyEvidence {
            platform,
            versions: vec![("cpython".into(), version.into())],
            artifacts: Vec::new(),
        }
    }

    fn assert_refuses(error: io::Error, why: &str) {
        let text = error.to_string();
        assert!(text.contains(why), "{text}");
        assert!(text.contains("tog update --toolchain"), "{text}");
        assert!(
            text.starts_with("cannot seed the python toolchain lock"),
            "{text}"
        );
    }

    #[test]
    fn seeds_from_a_recorded_exact_version_on_a_recorded_platform() {
        let catalog = python_catalog();
        let seeded = seed(&catalog, &evidence(Some(LINUX), "3.12.14")).unwrap();
        assert_eq!(seeded.release, "py312");
        // The seed is the recorded version, not the newest: no guessing
        // from the shipped default.
        assert_eq!(catalog.select(&Request::newest()).unwrap().release, "py313");
        assert_eq!(
            seed(&catalog, &evidence(Some(DARWIN), "3.12.14"))
                .unwrap()
                .release,
            "py312"
        );
    }

    #[test]
    fn refuses_without_platform_version_or_matching_release() {
        let catalog = python_catalog();
        assert_refuses(
            seed(&catalog, &evidence(None, "3.12.14")).unwrap_err(),
            "records no platform",
        );
        let no_version = LegacyEvidence {
            platform: Some(LINUX),
            ..LegacyEvidence::default()
        };
        assert_refuses(
            seed(&catalog, &no_version).unwrap_err(),
            "records no cpython version",
        );
        assert_refuses(
            seed(&catalog, &evidence(Some(LINUX), "3.12rc1")).unwrap_err(),
            "is not exact",
        );
        assert_refuses(
            seed(&catalog, &evidence(Some(LINUX), "3.12")).unwrap_err(),
            "no catalog release has cpython 3.12;",
        );
        assert_refuses(
            seed(&catalog, &evidence(Some(LINUX), "3.9.1")).unwrap_err(),
            "no catalog release has cpython 3.9.1",
        );
    }

    #[test]
    fn a_same_platform_closure_is_not_foreign_platform_evidence() {
        let catalog = python_catalog();
        // 3.11.16 exists for Darwin only. A Darwin closure proves the Darwin
        // row, but the lock needs the Linux row too, and the closure cannot
        // supply it.
        assert_refuses(
            seed(&catalog, &evidence(Some(DARWIN), "3.11.16")).unwrap_err(),
            "no complete x86_64-unknown-linux-gnu artifact set, and a closure realized on aarch64-apple-darwin is not evidence for x86_64-unknown-linux-gnu",
        );
        // A Linux closure recording a version the catalog only has for
        // Darwin refuses on its own platform first.
        assert_refuses(
            seed(&catalog, &evidence(Some(LINUX), "3.11.16")).unwrap_err(),
            "no complete x86_64-unknown-linux-gnu artifact set",
        );
    }

    #[test]
    fn proved_artifacts_tell_recipe_revisions_apart_and_refuse_strangers() {
        let mut r1 = bundle("py312-r1", "cpython", "3.12.14", Platform::ALL);
        r1.revision = Some(1);
        let mut r2 = r1.clone();
        r2.release = "py312-r2".into();
        r2.revision = Some(2);
        for row in &mut r2.artifacts {
            row.recipe = "example/2".into();
        }
        let catalog = Catalog::new("python", vec![r1, r2]).unwrap();
        // Version alone cannot choose between two revisions.
        assert_refuses(
            seed(&catalog, &evidence(Some(LINUX), "3.12.14")).unwrap_err(),
            "releases py312-r1, py312-r2 all have cpython 3.12.14",
        );
        let proof = |recipe: &str, fill: char| LegacyEvidence {
            platform: Some(LINUX),
            versions: vec![("cpython".into(), "3.12.14".into())],
            artifacts: vec![ProvedArtifact {
                component: "cpython".into(),
                recipe: recipe.into(),
                digest: sha256(fill),
            }],
        };
        assert_eq!(
            seed(&catalog, &proof("example/2", 'b')).unwrap().release,
            "py312-r2"
        );
        assert_eq!(
            seed(&catalog, &proof("example/1", 'b')).unwrap().release,
            "py312-r1"
        );
        // The proof is for the closure's platform: a Linux closure proving
        // the Darwin digest is a mismatch, not a match.
        assert_refuses(
            seed(&catalog, &proof("example/1", 'a')).unwrap_err(),
            "which no catalog release with cpython 3.12.14 carries",
        );
        assert_refuses(
            seed(&catalog, &proof("example/9", 'b')).unwrap_err(),
            "under recipe example/9",
        );
    }

    #[test]
    fn beam_needs_both_primary_versions() {
        let beam = Bundle {
            release: "beam".into(),
            revision: None,
            primary: vec!["otp".into(), "elixir".into()],
            components: vec![
                Component::new("otp", "29.0.5"),
                Component::new("elixir", "1.20.4"),
            ],
            artifacts: Platform::ALL
                .iter()
                .flat_map(|p| [row(*p, "otp", 'a'), row(*p, "elixir", 'b')])
                .collect(),
        };
        let catalog = Catalog::new("elixir", vec![beam]).unwrap();
        let otp_only = LegacyEvidence {
            platform: Some(LINUX),
            versions: vec![("otp".into(), "29.0.5".into())],
            artifacts: Vec::new(),
        };
        let error = seed(&catalog, &otp_only).unwrap_err().to_string();
        assert!(error.contains("records no elixir version"), "{error}");
        let both = LegacyEvidence {
            platform: Some(LINUX),
            versions: vec![
                ("elixir".into(), "1.20.4".into()),
                ("otp".into(), "29.0.5".into()),
            ],
            artifacts: Vec::new(),
        };
        assert_eq!(seed(&catalog, &both).unwrap().release, "beam");
    }
}

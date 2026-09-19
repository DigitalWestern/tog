//! Version selection over a catalog: the request grammar every ecosystem's
//! source reader lowers to, and the one global order a lock is minted from.
//!
//! Only releases complete on every supported platform are candidates, so an
//! asymmetric catalog selects the same bundle from either platform value.
//! Order: primary version descending, highest explicit revision (a bundle
//! with none loses to one with one; two without compare by newest catalog
//! order), then the provider/build/recipe tuple, the canonical artifact
//! tuple and the bundle id. Channel is not an ordering key: two bundles that
//! tie on primary version are the same upstream release.

use super::{invalid, qualified, Bundle, Catalog};
use std::cmp::Ordering;
use std::fmt;
use std::io;

/// A dotted numeric version (`3.12.14`, `24.20.0`, `9.0.317`): the only
/// shape a primary component may have. Compared component-wise with PEP
/// 440's zero padding, so `3.10` sorts above `3.9` and `1.2` equals
/// `1.2.0`; the spelling is kept for display.
#[derive(Clone, Debug)]
pub struct Version(Vec<u64>);

impl Version {
    /// The parts with trailing zeros dropped: what comparison sees.
    fn trimmed(&self) -> &[u64] {
        let mut end = self.0.len();
        while end > 1 && self.0[end - 1] == 0 {
            end -= 1;
        }
        &self.0[..end]
    }
}

impl PartialEq for Version {
    fn eq(&self, other: &Version) -> bool {
        self.trimmed() == other.trimmed()
    }
}

impl Eq for Version {}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Version) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Version) -> Ordering {
        self.trimmed().cmp(other.trimmed())
    }
}

impl std::hash::Hash for Version {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.trimmed().hash(state)
    }
}

impl Version {
    pub fn parse(text: &str) -> io::Result<Version> {
        let parts = text
            .split('.')
            .map(|piece| {
                if piece.is_empty()
                    || (piece.len() > 1 && piece.starts_with('0'))
                    || !piece.bytes().all(|b| b.is_ascii_digit())
                {
                    return None;
                }
                piece.parse::<u64>().ok()
            })
            .collect::<Option<Vec<u64>>>()
            .filter(|parts| !parts.is_empty())
            .ok_or_else(|| invalid(format!("not a dotted numeric version: {text:?}")))?;
        Ok(Version(parts))
    }

    pub fn parts(&self) -> &[u64] {
        &self.0
    }

    /// `3.12.14` starts with `3.12`; `3.120.0` does not.
    pub fn starts_with(&self, prefix: &Version) -> bool {
        let (parts, prefix) = (self.trimmed(), prefix.trimmed());
        parts.len() >= prefix.len() && parts[..prefix.len()] == prefix[..]
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text: Vec<String> = self.0.iter().map(u64::to_string).collect();
        f.write_str(&text.join("."))
    }
}

/// The comparison operators a range request may use: the supported subset
/// of PEP 440 (`>=`, `<`, `==`, `~=`, `!=`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    Ge,
    Lt,
    Eq,
    Ne,
    /// `~= X.Y.Z` is `>= X.Y.Z` and `== X.Y.*`.
    Compatible,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Specifier {
    op: Op,
    version: Version,
}

impl Specifier {
    /// `~=` needs at least two components (PEP 440); the others take any.
    pub fn new(op: Op, version: Version) -> io::Result<Specifier> {
        if op == Op::Compatible && version.0.len() < 2 {
            return Err(invalid(format!(
                "~={version} needs at least two version components"
            )));
        }
        Ok(Specifier { op, version })
    }

    pub fn matches(&self, candidate: &Version) -> bool {
        match self.op {
            Op::Ge => candidate >= &self.version,
            Op::Lt => candidate < &self.version,
            Op::Eq => candidate == &self.version,
            Op::Ne => candidate != &self.version,
            Op::Compatible => {
                let mut prefix = self.version.clone();
                prefix.0.pop();
                candidate >= &self.version && candidate.starts_with(&prefix)
            }
        }
    }
}

/// What a source file asks of one primary component.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VersionRequest {
    /// Exactly this version (`.node-version 24.20.0`); filters candidates to
    /// that primary version, so recipe revisions of it still order.
    Exact(Version),
    /// The newest release under this prefix (`.python-version 3.12`).
    Prefix(Version),
    /// The newest release satisfying every specifier (`>=3.11,<3.13`).
    Specifiers(Vec<Specifier>),
    /// The newest complete release.
    Newest,
}

impl VersionRequest {
    pub fn matches(&self, candidate: &Version) -> bool {
        match self {
            VersionRequest::Exact(version) => candidate == version,
            VersionRequest::Prefix(prefix) => candidate.starts_with(prefix),
            VersionRequest::Specifiers(specifiers) => {
                specifiers.iter().all(|s| s.matches(candidate))
            }
            VersionRequest::Newest => true,
        }
    }
}

impl fmt::Display for VersionRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VersionRequest::Exact(v) => write!(f, "=={v}"),
            VersionRequest::Prefix(v) => write!(f, "{v}.*"),
            VersionRequest::Specifiers(specifiers) => {
                let parts: Vec<String> = specifiers
                    .iter()
                    .map(|s| {
                        let op = match s.op {
                            Op::Ge => ">=",
                            Op::Lt => "<",
                            Op::Eq => "==",
                            Op::Ne => "!=",
                            Op::Compatible => "~=",
                        };
                        format!("{op}{}", s.version)
                    })
                    .collect();
                f.write_str(&parts.join(","))
            }
            VersionRequest::Newest => f.write_str("newest"),
        }
    }
}

/// A request over a bundle's primary components. An empty request is
/// "newest"; BEAM requests may name `otp` and `elixir` separately.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Request {
    pub components: Vec<(String, VersionRequest)>,
}

impl Request {
    pub fn newest() -> Request {
        Request::default()
    }

    pub fn exact(component: &str, version: &str) -> io::Result<Request> {
        Ok(Request::newest().with(component, VersionRequest::Exact(Version::parse(version)?)))
    }

    pub fn with(mut self, component: &str, request: VersionRequest) -> Request {
        self.components.push((component.into(), request));
        self
    }

    fn matches(&self, bundle: &Bundle, versions: &[Version]) -> io::Result<bool> {
        for (component, request) in &self.components {
            let index = bundle
                .primary
                .iter()
                .position(|name| name == component)
                .ok_or_else(|| {
                    invalid(format!(
                        "request names {component}, which is not a primary component of release {} ({})",
                        bundle.release,
                        bundle.primary.join(", ")
                    ))
                })?;
            if !request.matches(&versions[index]) {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

impl fmt::Display for Request {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.components.is_empty() {
            return f.write_str("newest");
        }
        let parts: Vec<String> = self
            .components
            .iter()
            .map(|(component, request)| format!("{component} {request}"))
            .collect();
        f.write_str(&parts.join("; "))
    }
}

/// A candidate with its precomputed ordering keys.
struct Ranked<'a> {
    bundle: &'a Bundle,
    index: usize,
    versions: Vec<Version>,
    provenance: Vec<(String, String, String, String, String)>,
    artifacts: Vec<(String, String, String, String)>,
    bundle_id: String,
}

impl<'a> Ranked<'a> {
    fn new(index: usize, bundle: &'a Bundle) -> io::Result<Ranked<'a>> {
        let mut provenance: Vec<_> = bundle
            .artifacts
            .iter()
            .map(|row| {
                (
                    row.platform.triple().to_string(),
                    row.component.clone(),
                    row.provider.clone(),
                    row.build.clone(),
                    row.recipe.clone(),
                )
            })
            .collect();
        provenance.sort();
        let mut artifacts: Vec<_> = bundle
            .artifacts
            .iter()
            .map(|row| {
                (
                    row.platform.triple().to_string(),
                    row.component.clone(),
                    row.url.clone(),
                    qualified(&row.digest),
                )
            })
            .collect();
        artifacts.sort();
        Ok(Ranked {
            bundle,
            index,
            versions: bundle.primary_versions()?,
            provenance,
            artifacts,
            bundle_id: bundle.bundle_id(),
        })
    }
}

/// The global order, best first.
fn order(a: &Ranked<'_>, b: &Ranked<'_>) -> Ordering {
    b.versions
        .cmp(&a.versions)
        .then_with(|| match (a.bundle.revision, b.bundle.revision) {
            (Some(x), Some(y)) => y.cmp(&x),
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (None, None) => b.index.cmp(&a.index),
        })
        .then_with(|| a.provenance.cmp(&b.provenance))
        .then_with(|| a.artifacts.cmp(&b.artifacts))
        .then_with(|| a.bundle_id.cmp(&b.bundle_id))
}

impl Catalog {
    /// The complete releases with their ordering keys, best first.
    fn ranked(&self) -> io::Result<Vec<Ranked<'_>>> {
        let mut ranked = self
            .bundles()
            .iter()
            .enumerate()
            .filter(|(_, bundle)| bundle.complete_everywhere())
            .map(|(index, bundle)| Ranked::new(index, bundle))
            .collect::<io::Result<Vec<_>>>()?;
        ranked.sort_by(order);
        Ok(ranked)
    }

    /// Every complete release in selection order, best first.
    pub fn ordered(&self) -> io::Result<Vec<&Bundle>> {
        Ok(self.ranked()?.into_iter().map(|r| r.bundle).collect())
    }

    /// The first complete release, in selection order, that satisfies
    /// `request`. Selection never consults the host platform.
    pub fn select(&self, request: &Request) -> io::Result<&Bundle> {
        let ranked = self.ranked()?;
        for candidate in &ranked {
            if request.matches(candidate.bundle, &candidate.versions)? {
                return Ok(candidate.bundle);
            }
        }
        Err(invalid(format!(
            "no complete {} release satisfies {request} ({} complete of {} in the catalog)",
            self.ecosystem(),
            ranked.len(),
            self.bundles().len()
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::super::fixtures::*;
    use super::super::{ArtifactRow, Component};
    use super::*;
    use crate::kernel::platform::Platform;

    const DARWIN: Platform = Platform::Aarch64AppleDarwin;
    const LINUX: Platform = Platform::X86_64UnknownLinuxGnu;

    fn v(text: &str) -> Version {
        Version::parse(text).unwrap()
    }

    #[test]
    fn versions_parse_and_compare_numerically() {
        assert!(v("3.10.0") > v("3.9.99"));
        assert_eq!(v("1.2"), v("1.2.0"));
        assert!(v("1.2") < v("1.2.1"));
        assert!(v("3.12.0") > v("3.11.99"));
        assert!(v("24.20.0").starts_with(&v("24.20")));
        assert!(v("3.12").starts_with(&v("3.12.0")));
        assert!(v("3.12.0").starts_with(&v("3.12")));
        assert!(!v("3.120.0").starts_with(&v("3.12")));
        assert_eq!(v("9.0.317").to_string(), "9.0.317");
        for bad in ["", "v1", "1..2", "1.02", "1.2-rc1", "3.12.14t", "."] {
            assert!(Version::parse(bad).is_err(), "{bad:?} parsed");
        }
    }

    #[test]
    fn specifiers_follow_the_supported_pep440_subset() {
        let spec = |op, text| Specifier::new(op, v(text)).unwrap();
        assert!(spec(Op::Ge, "3.11").matches(&v("3.11.0")));
        assert!(!spec(Op::Lt, "3.11").matches(&v("3.11.0")));
        assert!(spec(Op::Eq, "3.11.2").matches(&v("3.11.2")));
        assert!(spec(Op::Ne, "3.11.2").matches(&v("3.11.3")));
        assert!(spec(Op::Compatible, "3.11.2").matches(&v("3.11.9")));
        assert!(!spec(Op::Compatible, "3.11.2").matches(&v("3.12.0")));
        assert!(spec(Op::Compatible, "3.11").matches(&v("3.14.0")));
        assert!(!spec(Op::Compatible, "3.11").matches(&v("4.0.0")));
        assert!(Specifier::new(Op::Compatible, v("3")).is_err());
        assert!(spec(Op::Eq, "3.12").matches(&v("3.12.0")));
        assert!(!spec(Op::Eq, "3.12").matches(&v("3.12.1")));
        let range = VersionRequest::Specifiers(vec![spec(Op::Ge, "3.11"), spec(Op::Lt, "3.13")]);
        assert!(range.matches(&v("3.12.14")));
        assert!(!range.matches(&v("3.13.0")));
        assert_eq!(range.to_string(), ">=3.11,<3.13");
    }

    fn catalog(bundles: Vec<Bundle>) -> Catalog {
        Catalog::new("cpython", bundles).unwrap()
    }

    #[test]
    fn selects_only_from_the_intersection_of_complete_releases() {
        // Darwin-only A (newest), Linux-only B, complete C: C wins, and the
        // choice does not depend on any platform value.
        let a = bundle("a", "cpython", "3.14.0", &[DARWIN]);
        let b = bundle("b", "cpython", "3.13.0", &[LINUX]);
        let c = bundle("c", "cpython", "3.12.0", Platform::ALL);
        let catalog = catalog(vec![a, b, c]);
        let selected = catalog.select(&Request::newest()).unwrap();
        assert_eq!(selected.release, "c");
        // The selector takes no platform, so this literal is what either
        // host mints; a host input creeping back in would change it.
        assert_eq!(
            selected.bundle_id(),
            "sha256:acdec1e47e3a5504c55c7972baed5fb822da193aa1b1aaa038c41eb08e821caa"
        );
        assert_eq!(
            catalog
                .ordered()
                .unwrap()
                .iter()
                .map(|b| b.release.as_str())
                .collect::<Vec<_>>(),
            ["c"]
        );
        // An exact request for the incomplete release is a hard error.
        let error = catalog
            .select(&Request::exact("cpython", "3.14.0").unwrap())
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("no complete cpython release satisfies cpython ==3.14.0"),
            "{error}"
        );
        assert!(error.to_string().contains("1 complete of 3"), "{error}");
    }

    #[test]
    fn exact_prefix_and_range_requests_pick_the_first_satisfying_candidate() {
        let catalog = catalog(vec![
            bundle("py312", "cpython", "3.12.14", Platform::ALL),
            bundle("py313", "cpython", "3.13.15", Platform::ALL),
            bundle("py310", "cpython", "3.10.21", Platform::ALL),
            bundle("py311", "cpython", "3.11.16", Platform::ALL),
            bundle("py314", "cpython", "3.14.7", Platform::ALL),
        ]);
        assert_eq!(catalog.select(&Request::newest()).unwrap().release, "py314");
        assert_eq!(
            catalog
                .select(&Request::exact("cpython", "3.11.16").unwrap())
                .unwrap()
                .release,
            "py311"
        );
        let prefix = Request::newest().with("cpython", VersionRequest::Prefix(v("3.12")));
        assert_eq!(catalog.select(&prefix).unwrap().release, "py312");
        let range = Request::newest().with(
            "cpython",
            VersionRequest::Specifiers(vec![
                Specifier::new(Op::Ge, v("3.11")).unwrap(),
                Specifier::new(Op::Lt, v("3.13")).unwrap(),
            ]),
        );
        assert_eq!(catalog.select(&range).unwrap().release, "py312");
        let excluded = Request::newest().with(
            "cpython",
            VersionRequest::Specifiers(vec![Specifier::new(Op::Ne, v("3.14.7")).unwrap()]),
        );
        assert_eq!(catalog.select(&excluded).unwrap().release, "py313");
        // Exact requests match the primary version only: no prefix matching.
        assert!(catalog
            .select(&Request::exact("cpython", "3.12").unwrap())
            .is_err());
        // A request for a component that is not primary is an error, not a miss.
        let error = catalog
            .select(&Request::exact("uv", "0.1.0").unwrap())
            .unwrap_err();
        assert!(
            error.to_string().contains("not a primary component"),
            "{error}"
        );
    }

    #[test]
    fn revisions_of_one_version_order_by_explicit_revision_then_catalog_order() {
        let mut r1 = bundle("v1-r1", "node", "24.20.0", Platform::ALL);
        r1.revision = Some(1);
        let mut r2 = bundle("v1-r2", "node", "24.20.0", Platform::ALL);
        r2.revision = Some(2);
        r2.artifacts[0].recipe = "example/2".into();
        r2.artifacts[1].recipe = "example/2".into();
        let mut older = bundle("v0", "node", "24.19.0", Platform::ALL);
        older.revision = Some(9);
        let catalog = Catalog::new("node", vec![r2.clone(), r1.clone(), older]).unwrap();
        // Primary version first (revision 9 of the older version loses),
        // then the highest explicit revision regardless of catalog order.
        let ordered: Vec<&str> = catalog
            .ordered()
            .unwrap()
            .iter()
            .map(|b| b.release.as_str())
            .collect();
        assert_eq!(ordered, ["v1-r2", "v1-r1", "v0"]);
        // An exact request keeps both revisions as candidates and takes the first.
        assert_eq!(
            catalog
                .select(&Request::exact("node", "24.20.0").unwrap())
                .unwrap()
                .release,
            "v1-r2"
        );

        // Without explicit revisions the newest catalog row wins, and an
        // explicit revision beats none.
        let mut first = bundle("first", "node", "24.20.0", Platform::ALL);
        first.artifacts[0].recipe = "example/1".into();
        let mut second = bundle("second", "node", "24.20.0", Platform::ALL);
        second.artifacts[0].recipe = "example/2".into();
        let catalog = Catalog::new("node", vec![first.clone(), second.clone()]).unwrap();
        assert_eq!(
            catalog.select(&Request::newest()).unwrap().release,
            "second"
        );
        let mut explicit = first.clone();
        explicit.release = "explicit".into();
        explicit.revision = Some(1);
        explicit.artifacts[0].recipe = "example/0".into();
        let catalog = Catalog::new("node", vec![explicit, second]).unwrap();
        assert_eq!(
            catalog.select(&Request::newest()).unwrap().release,
            "explicit"
        );
    }

    #[test]
    fn equal_revisions_fall_through_to_provenance_artifacts_and_id() {
        let mut a = bundle("a", "node", "1.0.0", Platform::ALL);
        a.revision = Some(1);
        let mut b = a.clone();
        b.release = "b".into();
        b.artifacts[0].recipe = "example/0".into();
        let catalog = Catalog::new("node", vec![a.clone(), b.clone()]).unwrap();
        assert_eq!(catalog.select(&Request::newest()).unwrap().release, "b");
        // Same provenance tuple, different bytes: the artifact tuple decides.
        let mut c = a.clone();
        c.release = "c".into();
        c.artifacts[0].digest = sha256('0');
        let catalog = Catalog::new("node", vec![a.clone(), c]).unwrap();
        assert_eq!(catalog.select(&Request::newest()).unwrap().release, "c");
    }

    #[test]
    fn beam_compares_the_otp_elixir_pair_otp_first() {
        let beam = |release: &str, otp: &str, elixir: &str| Bundle {
            release: release.into(),
            revision: None,
            primary: vec!["otp".into(), "elixir".into()],
            components: vec![Component::new("otp", otp), Component::new("elixir", elixir)],
            artifacts: Platform::ALL
                .iter()
                .flat_map(|p| [row(*p, "otp", 'a'), row(*p, "elixir", 'b')])
                .collect(),
        };
        let catalog = Catalog::new(
            "elixir",
            vec![
                beam("old-otp-new-elixir", "28.3.0", "1.20.4"),
                beam("new-otp-old-elixir", "29.0.5", "1.19.0"),
                beam("new-otp-new-elixir", "29.0.5", "1.20.4"),
            ],
        )
        .unwrap();
        let ordered: Vec<&str> = catalog
            .ordered()
            .unwrap()
            .iter()
            .map(|b| b.release.as_str())
            .collect();
        assert_eq!(
            ordered,
            [
                "new-otp-new-elixir",
                "new-otp-old-elixir",
                "old-otp-new-elixir"
            ]
        );
        let exact = Request::exact("otp", "29.0.5")
            .unwrap()
            .with("elixir", VersionRequest::Exact(v("1.19.0")));
        assert_eq!(
            catalog.select(&exact).unwrap().release,
            "new-otp-old-elixir"
        );
        let only_elixir = Request::newest().with("elixir", VersionRequest::Prefix(v("1.20")));
        assert_eq!(
            catalog.select(&only_elixir).unwrap().release,
            "new-otp-new-elixir"
        );
    }

    #[test]
    fn a_bundle_with_embedded_components_selects_and_carries_them() {
        let mut node = bundle("node", "node", "24.20.0", Platform::ALL);
        node.components
            .push(Component::embedded("bundled-npm", "11.19.0", "node"));
        node.components
            .push(Component::embedded("node-gyp", "12.4.0", "bundled-npm"));
        let catalog = Catalog::new("node", vec![node]).unwrap();
        let selected = catalog.select(&Request::newest()).unwrap();
        assert_eq!(
            selected
                .component("node-gyp")
                .unwrap()
                .embedded_in
                .as_deref(),
            Some("bundled-npm")
        );
        assert!(selected.artifact(LINUX, "node-gyp").is_none());
        let _: &ArtifactRow = selected.artifact(LINUX, "node").unwrap();
    }
}

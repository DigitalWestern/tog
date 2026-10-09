//! The PyPI protocol (python tailor), as tog's resolution proxy serves it to
//! uv.
//!
//! uv reaches PyPI through TLS interception, not a mirror: `uv.lock` and
//! `requirements.lock.txt` record PyPI's own file URLs, so the proxy
//! terminates uv's tunnels to `pypi.org` and `files.pythonhosted.org` and
//! serves what it asks for there through this route:
//!
//! - `pypi.org/simple/<name>/`: the project page (PEP 691 JSON, which uv
//!   asks for, or PEP 503 HTML). Each file it lists names its URL and its
//!   hashes (`hashes` in JSON, a `#sha256=` fragment in HTML), and the
//!   hash of its core metadata when PyPI serves that separately
//!   (`core-metadata`, PEP 714, or the older `data-dist-info-metadata`).
//!   Those are the route's claims.
//! - `files.pythonhosted.org/packages/...`: a wheel or sdist, verified
//!   against its page's claim, and a wheel's `<file>.metadata` (PEP 658),
//!   which is how uv resolves without downloading wheels.
//!
//! Anything else on either host is refused. An extra index a project
//! names (`[[tool.uv.index]]`), a direct-URL requirement, and a git
//! dependency are not this route's: they reach the proxy as unattested
//! hosts or git fetches (see `kernel::resolve::intercept`).

use crate::kernel::fetch::Digest;
use crate::kernel::resolve::routes::{
    Claim, Endpoint, RegistryProtocol, RequestClass, Route, Upstream,
};
use std::io;
use url::Url;

/// The route id the ledger and the diagnostics name.
pub const ROUTE_ID: &str = "pypi";
/// The index host.
pub const INDEX_HOST: &str = "pypi.org";
/// The file host.
pub const FILES_HOST: &str = "files.pythonhosted.org";
/// The index as uv is told it: the default index forced on every uv run.
pub const INDEX_URL: &str = "https://pypi.org/simple";

/// The longest project name this grammar accepts.
const MAX_NAME: usize = 256;
/// The longest path segment under `/packages/`.
const MAX_SEGMENT: usize = 512;
/// The most segments a file path has under `/packages/` (PyPI's hashed
/// layout uses four, the legacy `<pyver>/<letter>/<name>/<file>` four too).
const MAX_FILE_DEPTH: usize = 6;
/// The suffix of a wheel's separately served core metadata (PEP 658).
const METADATA_SUFFIX: &str = ".metadata";
/// The distribution file types PyPI serves.
const DIST_SUFFIXES: [&str; 6] = [".whl", ".tar.gz", ".zip", ".tar.bz2", ".tgz", ".egg"];

/// The PyPI protocol.
pub struct PypiRegistry;

pub static PYPI_REGISTRY: PypiRegistry = PypiRegistry;

impl RegistryProtocol for PypiRegistry {
    fn route_id(&self) -> &'static str {
        ROUTE_ID
    }

    fn upstream(&self, endpoints: &[Endpoint], path: &str) -> io::Result<Upstream> {
        if path.contains('?') {
            return Err(refused(path, "a PyPI request carries no query"));
        }
        let host = match check_path(path) {
            Ok(host) => host,
            Err(why) => return Err(refused(path, &why)),
        };
        Ok(Upstream::Fetch(endpoint(endpoints, host)?.url(path)?))
    }

    fn classify(&self, url: &Url) -> RequestClass {
        if url.host_str() == Some(FILES_HOST) {
            // Wheel metadata is immutable, claimed content too. Routing it
            // as revalidatable metadata would bypass digest verification.
            RequestClass::Artifact
        } else {
            RequestClass::Index
        }
    }

    /// Each file a project page lists, on the file host, claimed by its
    /// strongest hash, and its core metadata by the hash the page gives
    /// for it.
    fn claims(&self, url: &Url, body: &[u8]) -> Vec<(Url, Claim)> {
        if url.host_str() != Some(INDEX_HOST) || !url.path().starts_with("/simple/") {
            return Vec::new();
        }
        let Ok(text) = std::str::from_utf8(body) else {
            return Vec::new();
        };
        let files = match serde_json::from_str::<serde_json::Value>(text) {
            Ok(page) => json_files(&page),
            Err(_) => html_files(text),
        };
        let mut claims = Vec::new();
        for file in files {
            let Ok(target) = url.join(&file.href) else {
                continue;
            };
            let mut target = target;
            target.set_fragment(None);
            if target.host_str() != Some(FILES_HOST) || check_file_path(target.path()).is_err() {
                continue;
            }
            if let Some(claim) = strongest(&file.hashes) {
                claims.push((target.clone(), claim));
            }
            if let Some(claim) = strongest(&file.metadata) {
                if let Ok(metadata) = Url::parse(&format!("{target}{METADATA_SUFFIX}")) {
                    claims.push((metadata, claim));
                }
            }
        }
        claims
    }

    /// PyPI publishes a digest for every file it serves.
    fn expects_claim(&self, url: &Url) -> bool {
        url.host_str() == Some(FILES_HOST)
    }
}

/// One file a project page lists: its link as written, and the hashes the
/// page gives for it and for its core metadata (`(algorithm, hex)`).
struct ListedFile {
    href: String,
    hashes: Vec<(String, String)>,
    metadata: Vec<(String, String)>,
}

/// The files of a PEP 691 JSON page.
fn json_files(page: &serde_json::Value) -> Vec<ListedFile> {
    let pairs = |value: Option<&serde_json::Value>| -> Vec<(String, String)> {
        value
            .and_then(|value| value.as_object())
            .into_iter()
            .flatten()
            .filter_map(|(algo, hex)| Some((algo.to_ascii_lowercase(), hex.as_str()?.to_string())))
            .collect()
    };
    page.get("files")
        .and_then(|files| files.as_array())
        .into_iter()
        .flatten()
        .filter_map(|file| {
            let href = file.get("url")?.as_str()?.to_string();
            // PEP 714 renamed the key; a page may carry either, and a bare
            // `true` names no hash.
            let metadata = file
                .get("core-metadata")
                .filter(|value| value.is_object())
                .or_else(|| file.get("data-dist-info-metadata"));
            Some(ListedFile {
                href,
                hashes: pairs(file.get("hashes")),
                metadata: pairs(metadata),
            })
        })
        .collect()
}

/// The files of a PEP 503 HTML page: each anchor's `href` (its `#<algo>=<hex>`
/// fragment is the file's hash) and its `data-core-metadata` (or
/// `data-dist-info-metadata`) `<algo>=<hex>`.
fn html_files(text: &str) -> Vec<ListedFile> {
    let mut files = Vec::new();
    let mut rest = text;
    while let Some(start) = find_ascii_ci(rest, "<a ") {
        let tag_rest = &rest[start..];
        let end = tag_rest.find('>').unwrap_or(tag_rest.len());
        let tag = &tag_rest[..end];
        rest = &tag_rest[end..];
        let Some(href) = attribute(tag, "href") else {
            continue;
        };
        let href = unescape(&href);
        let hashes = href
            .split_once('#')
            .and_then(|(_, fragment)| hash_pair(fragment))
            .into_iter()
            .collect();
        let metadata = attribute(tag, "data-core-metadata")
            .or_else(|| attribute(tag, "data-dist-info-metadata"))
            .and_then(|value| hash_pair(&unescape(&value)))
            .into_iter()
            .collect();
        files.push(ListedFile {
            href,
            hashes,
            metadata,
        });
    }
    files
}

fn find_ascii_ci(haystack: &str, needle: &str) -> Option<usize> {
    haystack
        .as_bytes()
        .windows(needle.len())
        .position(|window| window.eq_ignore_ascii_case(needle.as_bytes()))
}

/// The value of `name="..."` (or single-quoted) in an HTML tag.
fn attribute(tag: &str, name: &str) -> Option<String> {
    let mut search = tag;
    loop {
        let at = find_ascii_ci(search, name)?;
        let before = search[..at].chars().last();
        let after = &search[at + name.len()..];
        search = after;
        if !before.is_some_and(char::is_whitespace) {
            continue;
        }
        let Some(value) = after.trim_start().strip_prefix('=') else {
            continue;
        };
        let value = value.trim_start();
        let quote = value.chars().next()?;
        if quote != '"' && quote != '\'' {
            continue;
        }
        let inner = &value[1..];
        let close = inner.find(quote)?;
        return Some(inner[..close].to_string());
    }
}

/// The few entities a PyPI page writes inside attributes.
fn unescape(value: &str) -> String {
    value
        .replace("&amp;", "&")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
}

/// `<algo>=<hex>`.
fn hash_pair(text: &str) -> Option<(String, String)> {
    let (algo, hex) = text.split_once('=')?;
    Some((algo.to_ascii_lowercase(), hex.to_string()))
}

/// The claim of the strongest algorithm tog reads among `hashes`: sha512,
/// then sha256, then sha1 (weak). An md5 alone claims nothing, so its
/// artifact is unclaimed and `weak-integrity`.
fn strongest(hashes: &[(String, String)]) -> Option<Claim> {
    for algo in ["sha512", "sha256", "sha1"] {
        if let Some((_, hex)) = hashes.iter().find(|(name, _)| name == algo) {
            if let Ok(digest) = Digest::from_parts(algo, &hex.to_ascii_lowercase()) {
                return Some(Claim::one(digest));
            }
        }
    }
    None
}

/// The route endpoint on `host`, which a PyPI route always has.
fn endpoint<'a>(endpoints: &'a [Endpoint], host: &str) -> io::Result<&'a Endpoint> {
    endpoints
        .iter()
        .find(|endpoint| endpoint.host() == host)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("the PyPI route has no {host} endpoint"),
            )
        })
}

fn refused(path: &str, why: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("PyPI path {path:?} refused: {why}"),
    )
}

/// Which host serves `path`, else why it is not a PyPI path.
fn check_path(path: &str) -> Result<&'static str, String> {
    if let Some(rest) = path.strip_prefix("/simple/") {
        let name = rest.strip_suffix('/').unwrap_or(rest);
        if name.is_empty() {
            return Ok(INDEX_HOST);
        }
        check_name(name)?;
        return Ok(INDEX_HOST);
    }
    if path.starts_with("/packages/") {
        check_file_path(path)?;
        return Ok(FILES_HOST);
    }
    Err("not a project page (/simple/<name>/) or a file (/packages/...)".into())
}

/// A project name as a page path spells it: letters, digits, `.`, `_`,
/// `-`, not starting with `.`.
fn check_name(name: &str) -> Result<(), String> {
    let valid = !name.is_empty()
        && name.len() <= MAX_NAME
        && !name.starts_with('.')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    if valid {
        Ok(())
    } else {
        Err(format!("{name:?} is not a project name"))
    }
}

/// `/packages/<dir>/.../<file>`: plain segments, the last a distribution
/// file or its `.metadata`.
fn check_file_path(path: &str) -> Result<(), String> {
    let rest = path
        .strip_prefix("/packages/")
        .ok_or("a file is under /packages/")?;
    let parts: Vec<&str> = rest.split('/').collect();
    if parts.len() < 2 || parts.len() > MAX_FILE_DEPTH {
        return Err("a file is /packages/<directories>/<file>".into());
    }
    for part in &parts {
        let valid = !part.is_empty()
            && part.len() <= MAX_SEGMENT
            && !part.starts_with('.')
            && part.bytes().all(|b| {
                b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'+' | b'!')
            });
        if !valid {
            return Err(format!("{part:?} is not a file path segment"));
        }
    }
    let file = parts[parts.len() - 1];
    let file = file.strip_suffix(METADATA_SUFFIX).unwrap_or(file);
    if !DIST_SUFFIXES.iter().any(|suffix| file.ends_with(suffix)) {
        return Err(format!("{file:?} is not a distribution file"));
    }
    Ok(())
}

/// The PyPI route: the index and the file host.
pub fn route() -> io::Result<Route> {
    Route::new(
        &PYPI_REGISTRY,
        vec![Endpoint::https(INDEX_HOST)?, Endpoint::https(FILES_HOST)?],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoints() -> Vec<Endpoint> {
        vec![
            Endpoint::https(INDEX_HOST).unwrap(),
            Endpoint::https(FILES_HOST).unwrap(),
        ]
    }

    fn fetch(path: &str) -> String {
        match PYPI_REGISTRY.upstream(&endpoints(), path).unwrap() {
            Upstream::Fetch(url) => url.to_string(),
            other => panic!("{path}: {other:?}"),
        }
    }

    const WHEEL: &str = "/packages/d9/5a/e7c31adbe875f2abbb91bd84cf2dc52d792b5a01506781dbcf25c91daf11/six-1.16.0-py2.py3-none-any.whl";

    #[test]
    fn pages_and_files_map_onto_their_hosts() {
        for path in [
            "/simple/",
            "/simple/six/",
            "/simple/Zope.Interface",
            "/simple/a_b-c/",
        ] {
            assert_eq!(fetch(path), format!("https://{INDEX_HOST}{path}"));
        }
        for path in [
            WHEEL.to_string(),
            format!("{WHEEL}.metadata"),
            "/packages/source/s/six/six-1.16.0.tar.gz".to_string(),
            "/packages/ab/cd/ef/torch-2.1.0+cpu-cp312-cp312-linux_x86_64.whl".to_string(),
        ] {
            assert_eq!(fetch(&path), format!("https://{FILES_HOST}{path}"));
        }
        let page = Url::parse("https://pypi.org/simple/six/").unwrap();
        let wheel = Url::parse(&format!("https://{FILES_HOST}{WHEEL}")).unwrap();
        let metadata = Url::parse(&format!("https://{FILES_HOST}{WHEEL}.metadata")).unwrap();
        assert_eq!(PYPI_REGISTRY.classify(&page), RequestClass::Index);
        assert_eq!(PYPI_REGISTRY.classify(&wheel), RequestClass::Artifact);
        assert_eq!(PYPI_REGISTRY.classify(&metadata), RequestClass::Artifact);
        assert!(PYPI_REGISTRY.expects_claim(&wheel));
        assert!(PYPI_REGISTRY.expects_claim(&metadata));
        assert!(!PYPI_REGISTRY.expects_claim(&page));
    }

    #[test]
    fn the_pypi_grammar_refuses_everything_else() {
        for (path, needle) in [
            ("/simple/six/?format=json", "no query"),
            ("/pypi/six/json", "not a project page"),
            ("/simple/.hidden/", "not a project name"),
            ("/simple/a b/", "not a project name"),
            ("/simple/six/extra/", "not a project name"),
            ("/packages/six.whl", "/packages/<directories>/<file>"),
            ("/packages/aa/bb/six-1.0.txt", "not a distribution file"),
            ("/packages/aa/.git/six-1.0.whl", "not a file path segment"),
            (
                "/packages/a/b/c/d/e/f/six-1.0.whl",
                "/packages/<directories>/<file>",
            ),
            ("/", "not a project page"),
        ] {
            let error = PYPI_REGISTRY
                .upstream(&endpoints(), path)
                .unwrap_err()
                .to_string();
            assert!(error.contains(needle), "{path}: {error}");
        }
    }

    /// The recorded `six` page claims the recorded wheel's sha256 and its
    /// core metadata's.
    #[test]
    fn a_json_page_claims_its_files_and_their_metadata() {
        use sha2::{Digest as _, Sha256};
        let fixtures = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/proxy/registry/python");
        let body = std::fs::read(fixtures.join("pypi.org/simple/six/_index.body")).unwrap();
        let page = Url::parse("https://pypi.org/simple/six/").unwrap();
        let claims = PYPI_REGISTRY.claims(&page, &body);
        let metadata_bytes = std::fs::read(
            fixtures.join(format!("{FILES_HOST}{WHEEL}.metadata.body").trim_start_matches('/')),
        )
        .unwrap();
        let metadata = Url::parse(&format!("https://{FILES_HOST}{WHEEL}.metadata")).unwrap();
        let (_, claim) = claims
            .iter()
            .find(|(url, _)| *url == metadata)
            .expect("the metadata is claimed");
        assert_eq!(claim.algo(), "sha256");
        assert_eq!(
            claim.digests()[0].hex(),
            hex::encode(Sha256::digest(&metadata_bytes))
        );
        let wheel = Url::parse(&format!("https://{FILES_HOST}{WHEEL}")).unwrap();
        assert!(claims.iter().any(|(url, _)| *url == wheel));
        assert!(claims.len() > 20, "every file is claimed");
        // Nothing but a project page on the index host claims anything.
        assert!(PYPI_REGISTRY.claims(&wheel, &body).is_empty());
        assert!(PYPI_REGISTRY
            .claims(
                &Url::parse("https://pypi.org/pypi/six/json").unwrap(),
                &body
            )
            .is_empty());
    }

    #[test]
    fn mismatched_wheel_metadata_hard_fails_and_never_poison_caches() {
        use crate::kernel::policy::Policy;
        use crate::kernel::resolve::session::Mode;
        use crate::kernel::resolve::testing::{get, Harness, Reach, TEST_ORIGIN_PUBLIC};
        use crate::kernel::testutil::upstream::{Behavior, Reply};
        use sha2::{Digest as _, Sha256};
        let harness = Harness::serving(
            "pypi-metadata-mismatch",
            Reach::public(|_, _| vec![TEST_ORIGIN_PUBLIC.parse().unwrap()]),
            &[INDEX_HOST, FILES_HOST],
            "python",
        );
        let path = format!("{WHEEL}.metadata");
        let poisoned = b"Name: six\nVersion: 1.16.0\nRequires-Dist: injected\n";
        harness
            .upstream
            .set(&path, Behavior::Reply(Reply::new(200, poisoned)));
        let mut config = harness.config(Policy::default(), Mode::Online);
        config.routes = vec![route().unwrap()];
        let (session, address) = harness.open(config);
        let fetch = |path: &str| {
            get(
                &address,
                &format!(
                    "{}{}",
                    address.route_base(ROUTE_ID),
                    path.trim_start_matches('/')
                ),
                "",
            )
        };
        assert_eq!(fetch("/simple/six/").status, 200);
        assert_eq!(fetch(&path).status, 502);
        let report = session.finish();
        assert!(!report.facts.hard_failures.is_empty());
        let poisoned_hash = hex::encode(Sha256::digest(poisoned));
        assert!(!harness
            .store
            .root
            .join("cache/sha256")
            .join(poisoned_hash)
            .exists());
        assert!(report
            .ledger
            .entries()
            .any(|entry| entry.status == 502 && !entry.verified));

        // A later session must fetch and verify the restored sidecar,
        // rather than serving a poisoned metadata-cache copy.
        let fixtures = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/proxy/registry/python");
        let good = std::fs::read(fixtures.join(format!("{FILES_HOST}{path}.body"))).unwrap();
        harness
            .upstream
            .set(&path, Behavior::Reply(Reply::new(200, &good)));
        let mut config = harness.config(Policy::default(), Mode::Online);
        config.routes = vec![route().unwrap()];
        let (session, address) = harness.open(config);
        let fetch = |path: &str| {
            get(
                &address,
                &format!(
                    "{}{}",
                    address.route_base(ROUTE_ID),
                    path.trim_start_matches('/')
                ),
                "",
            )
        };
        assert_eq!(fetch("/simple/six/").status, 200);
        let response = fetch(&path);
        assert_eq!(response.status, 200);
        assert_eq!(response.body, good);
        assert!(session
            .finish()
            .ledger
            .entries()
            .any(|entry| entry.verified));
    }

    #[test]
    fn an_html_page_claims_by_fragment_and_metadata_attribute() {
        let sha = "a".repeat(64);
        let meta = "b".repeat(64);
        let html = format!(
            "<!DOCTYPE html><html><body>\n\
             <a href=\"https://files.pythonhosted.org/packages/aa/bb/x-1.0-py3-none-any.whl#sha256={sha}\" \
             data-requires-python=\"&gt;=3.8\" data-core-metadata=\"sha256={meta}\">x-1.0-py3-none-any.whl</a><br/>\n\
             <A HREF='../../packages/cc/dd/x-1.0.tar.gz#md5=0123456789abcdef0123456789abcdef'>x-1.0.tar.gz</A>\n\
             <a href=\"https://elsewhere.test/packages/aa/bb/x-2.0.whl#sha256={sha}\">x-2.0.whl</a>\n\
             </body></html>"
        );
        let page = Url::parse("https://pypi.org/simple/x/").unwrap();
        let claims = PYPI_REGISTRY.claims(&page, html.as_bytes());
        let urls: Vec<String> = claims.iter().map(|(url, _)| url.to_string()).collect();
        assert_eq!(
            urls,
            [
                "https://files.pythonhosted.org/packages/aa/bb/x-1.0-py3-none-any.whl",
                "https://files.pythonhosted.org/packages/aa/bb/x-1.0-py3-none-any.whl.metadata",
            ],
            "the md5-only sdist is unclaimed (weak), the other host is not this route's"
        );
        assert_eq!(claims[0].1.digests()[0].hex(), sha);
        assert_eq!(claims[1].1.digests()[0].hex(), meta);
    }

    #[test]
    fn the_strongest_hash_wins_and_md5_claims_nothing() {
        let pairs = |list: &[(&str, &str)]| -> Vec<(String, String)> {
            list.iter()
                .map(|(a, h)| (a.to_string(), h.to_string()))
                .collect()
        };
        let sha256 = "c".repeat(64);
        let sha512 = "d".repeat(128);
        let claim = strongest(&pairs(&[("sha256", &sha256), ("sha512", &sha512)])).unwrap();
        assert_eq!(claim.algo(), "sha512");
        let claim = strongest(&pairs(&[("md5", "0"), ("sha256", &sha256.to_uppercase())])).unwrap();
        assert_eq!(claim.algo(), "sha256");
        assert!(strongest(&pairs(&[("md5", &"e".repeat(32))])).is_none());
        assert!(strongest(&pairs(&[("sha1", &"f".repeat(40))]))
            .unwrap()
            .is_weak());
    }
}

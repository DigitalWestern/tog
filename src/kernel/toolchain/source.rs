//! Source policy (kernel layer): which publishers may serve toolchain
//! artifacts, from which endpoints, with which credential *reference*.
//!
//! The shipped defaults are configuration, not a compiled allow-list baked
//! into lock validity: a lock stays valid when policy tightens, and
//! retrieval refuses instead. Every toolchain artifact download
//! (`kernel::fetch::download_toolchain_artifact_held`) checks the row's URL
//! against the effective policy under the row's own `provider` before it
//! looks in the cache, and checks every redirect `Location` again before
//! requesting it, so a redirect off the publisher's endpoints refuses.
//! Package-registry downloads (npm, PyPI, crates, gems) are not toolchain
//! rows and do not pass through here.
//!
//! An endpoint may name a credential *reference*, and a redirect is matched
//! to the target endpoint, so it would get that endpoint's credential or
//! none, never the original endpoint's. No shipped endpoint names one, and
//! retrieval sends none (the credential policy is decided in #72; sending
//! is not built yet, #404). No secret is
//! ever stored here or in a catalog row: a [`CredentialRef`] names where an
//! operator keeps one.

use super::invalid;
use std::io;
use std::sync::OnceLock;

/// A named reference to a credential held outside tog (an environment
/// variable or keychain entry an operator configures). Never the secret.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialRef {
    pub name: String,
}

/// One authorized URL prefix: an `https://` origin plus an optional path
/// prefix, so a policy can admit `https://github.com/astral-sh/uv/` without
/// admitting every repository on that host.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint {
    pub base: String,
    pub credential: Option<CredentialRef>,
}

impl Endpoint {
    /// An anonymous endpoint. `base` must be `https://host[:port]/...`.
    pub fn new(base: &str) -> io::Result<Endpoint> {
        Endpoint::validate_base(base)?;
        Ok(Endpoint {
            base: base.into(),
            credential: None,
        })
    }

    #[cfg(test)]
    /// An endpoint that sends the referenced credential, and only there.
    pub fn with_credential(base: &str, credential: &str) -> io::Result<Endpoint> {
        let mut endpoint = Endpoint::new(base)?;
        if credential.is_empty() {
            return Err(invalid("credential reference is empty"));
        }
        endpoint.credential = Some(CredentialRef {
            name: credential.into(),
        });
        Ok(endpoint)
    }

    fn validate_base(base: &str) -> io::Result<()> {
        let rest = base
            .strip_prefix("https://")
            .ok_or_else(|| invalid(format!("endpoint {base:?} is not https://")))?;
        let host = rest.split('/').next().unwrap_or("");
        if host.is_empty() || host.contains('@') || host.contains('?') || host.contains('#') {
            return Err(invalid(format!("endpoint {base:?} has no plain host")));
        }
        Ok(())
    }

    /// Does `url` fall under this endpoint? The origin must match exactly
    /// (no suffix matching) and the path must extend the base's path at a
    /// segment boundary. A path that a server or client could normalize to
    /// somewhere else (`.`/`..` segments, backslashes, or a percent-escape
    /// that decodes to `/`, `\`, `.` or `%`) is never covered, so a prefix
    /// cannot be escaped by spelling. Inert escapes such as the `%2B` in a
    /// python-build-standalone file name are fine; overlong UTF-8 spellings
    /// are not decoded here, since every shipped endpoint rejects them.
    pub fn covers(&self, url: &str) -> bool {
        let Some(rest) = url.strip_prefix("https://") else {
            return false;
        };
        let base_rest = &self.base["https://".len()..];
        let (base_host, base_path) = split_host(base_rest);
        let (host, path) = split_host(rest);
        if host != base_host {
            return false;
        }
        let path = path.split(['?', '#']).next().unwrap_or("");
        if path.contains('\\')
            || !escapes_are_inert(path)
            || path
                .split('/')
                .any(|segment| segment == "." || segment == "..")
        {
            return false;
        }
        let base_path = base_path.trim_end_matches('/');
        if base_path.is_empty() {
            return true;
        }
        path == base_path || path.starts_with(&format!("{base_path}/"))
    }
}

/// Every `%XX` in `path` is well formed and decodes to a byte that cannot
/// change which directory the path names once a server decodes it.
fn escapes_are_inert(path: &str) -> bool {
    let bytes = path.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let Some(hex) = bytes.get(i + 1..i + 3) else {
                return false;
            };
            if !hex.iter().all(u8::is_ascii_hexdigit) {
                return false;
            }
            let Ok(decoded) = u8::from_str_radix(std::str::from_utf8(hex).expect("hex digits"), 16)
            else {
                return false;
            };
            if matches!(decoded, b'/' | b'\\' | b'.' | b'%') {
                return false;
            }
            i += 3;
        } else {
            i += 1;
        }
    }
    true
}

fn split_host(rest: &str) -> (&str, &str) {
    match rest.find('/') {
        Some(index) => (&rest[..index], &rest[index..]),
        None => (rest, ""),
    }
}

/// A publisher: the `provider` a catalog row names, and the endpoints that
/// may serve its artifacts (including the CDN origins its downloads redirect
/// to).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Publisher {
    pub id: String,
    pub endpoints: Vec<Endpoint>,
}

/// The effective source policy: the shipped defaults, plus whatever an
/// operator adds through [`SourcePolicy::allow`]. Later layers load and
/// protect it; this is the typed interface they fill.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SourcePolicy {
    publishers: Vec<Publisher>,
}

#[cfg(test)]
thread_local! {
    static TEST_POLICY: std::cell::Cell<Option<&'static SourcePolicy>> =
        const { std::cell::Cell::new(None) };
}

/// What an authorized fetch may do: contact `endpoint` on behalf of
/// `publisher`. The endpoint's credential reference, if it has one, is the
/// only credential that hop could carry; retrieval sends none today (#72).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Authorized<'a> {
    pub publisher: &'a str,
    pub endpoint: &'a Endpoint,
}

impl SourcePolicy {
    /// No publisher at all: every fetch refuses until one is allowed.
    pub fn empty() -> SourcePolicy {
        SourcePolicy::default()
    }

    /// The upstream endpoints the shipped catalog rows are served from.
    /// Defaults an operator may replace; not a validity rule for locks.
    pub fn shipped() -> SourcePolicy {
        let mut policy = SourcePolicy::empty();
        // A GitHub release download redirects to the asset CDN; both hops
        // are the same publisher's endpoints.
        let github_publisher = |policy: &mut SourcePolicy, id: &str, repo: &str| {
            let bases = [
                format!("https://github.com/{repo}/releases/download/"),
                "https://objects.githubusercontent.com/".to_string(),
                "https://release-assets.githubusercontent.com/".to_string(),
            ];
            for base in bases {
                policy
                    .allow(id, Endpoint::new(&base).expect("shipped endpoint"))
                    .expect("shipped publisher");
            }
        };
        github_publisher(
            &mut policy,
            "python-build-standalone",
            "astral-sh/python-build-standalone",
        );
        github_publisher(&mut policy, "uv", "astral-sh/uv");
        github_publisher(
            &mut policy,
            "homebrew-portable-ruby",
            "Homebrew/homebrew-portable-ruby",
        );
        github_publisher(&mut policy, "erlef-otp-builds", "erlef/otp_builds");
        github_publisher(
            &mut policy,
            "tog-toolchains",
            "DigitalWestern/tog-toolchains",
        );
        github_publisher(&mut policy, "elixir-lang", "elixir-lang/elixir");
        for (id, base) in [
            ("nodejs.org", "https://nodejs.org/dist/"),
            ("static.rust-lang.org", "https://static.rust-lang.org/dist/"),
            ("go.dev", "https://go.dev/dl/"),
            ("go.dev", "https://dl.google.com/go/"),
            ("builds.hex.pm", "https://builds.hex.pm/"),
            (
                "builds.dotnet.microsoft.com",
                "https://builds.dotnet.microsoft.com/dotnet/",
            ),
        ] {
            policy
                .allow(id, Endpoint::new(base).expect("shipped endpoint"))
                .expect("shipped publisher");
        }
        policy
    }

    /// The policy every toolchain download is checked against: the shipped
    /// defaults, built once per process. Nothing configures it yet.
    pub fn effective() -> &'static SourcePolicy {
        #[cfg(test)]
        if let Some(policy) = TEST_POLICY.with(std::cell::Cell::get) {
            return policy;
        }
        static EFFECTIVE: OnceLock<SourcePolicy> = OnceLock::new();
        EFFECTIVE.get_or_init(SourcePolicy::shipped)
    }

    /// Run `body` with `policy` as this thread's effective policy, for unit
    /// tests whose rows point at a local address the shipped policy refuses.
    /// The shipped policy itself is never loosened.
    #[cfg(test)]
    pub(crate) fn with_test_policy<R>(policy: SourcePolicy, body: impl FnOnce() -> R) -> R {
        struct Restore(Option<&'static SourcePolicy>);
        impl Drop for Restore {
            fn drop(&mut self) {
                TEST_POLICY.with(|cell| cell.set(self.0));
            }
        }
        let leaked: &'static SourcePolicy = Box::leak(Box::new(policy));
        let _restore = Restore(TEST_POLICY.with(|cell| cell.replace(Some(leaked))));
        body()
    }

    #[cfg(test)]
    pub fn publishers(&self) -> &[Publisher] {
        &self.publishers
    }

    pub fn publisher(&self, id: &str) -> Option<&Publisher> {
        self.publishers.iter().find(|p| p.id == id)
    }

    /// Admit `endpoint` for `publisher`, creating the publisher if new. This
    /// is an explicit configuration change, never a side effect of a lock.
    pub fn allow(&mut self, publisher: &str, endpoint: Endpoint) -> io::Result<()> {
        if publisher.is_empty() {
            return Err(invalid("publisher id is empty"));
        }
        match self.publishers.iter_mut().find(|p| p.id == publisher) {
            Some(existing) => {
                if !existing.endpoints.contains(&endpoint) {
                    existing.endpoints.push(endpoint);
                }
            }
            None => self.publishers.push(Publisher {
                id: publisher.into(),
                endpoints: vec![endpoint],
            }),
        }
        Ok(())
    }

    /// May `url` be fetched on behalf of `publisher`? Only `https://` URLs
    /// under one of that publisher's endpoints; `file://`, `http://` and
    /// any other publisher's endpoint refuse before any network activity.
    /// Call it again for every redirect `Location`.
    pub fn authorize<'a>(&'a self, publisher: &str, url: &str) -> io::Result<Authorized<'a>> {
        let refuse = |why: &str| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "source policy refuses {} for {publisher}: {why}",
                    crate::kernel::fetch::shown_url(url)
                ),
            )
        };
        if !url.starts_with("https://") {
            return Err(refuse(
                "only https:// endpoints may serve toolchain artifacts",
            ));
        }
        let Some(found) = self.publisher(publisher) else {
            return Err(refuse("no such publisher in the effective policy"));
        };
        found
            .endpoints
            .iter()
            .find(|endpoint| endpoint.covers(url))
            .map(|endpoint| Authorized {
                publisher: &found.id,
                endpoint,
            })
            .ok_or_else(|| refuse("not under any endpoint authorized for this publisher"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoints_match_origin_exactly_and_paths_at_segment_boundaries() {
        let endpoint = Endpoint::new("https://github.com/astral-sh/uv/releases/download/").unwrap();
        assert!(
            endpoint.covers("https://github.com/astral-sh/uv/releases/download/0.12.7/uv.tar.gz")
        );
        assert!(endpoint.covers("https://github.com/astral-sh/uv/releases/download?x=1"));
        assert!(!endpoint.covers("https://github.com/astral-sh/uv/releases/downloads/x"));
        assert!(!endpoint.covers("https://github.com/astral-sh/other/releases/download/x"));
        assert!(
            !endpoint.covers("https://github.com.evil.example/astral-sh/uv/releases/download/x")
        );
        assert!(
            !endpoint.covers("https://evil.example/github.com/astral-sh/uv/releases/download/x")
        );
        assert!(!endpoint.covers("http://github.com/astral-sh/uv/releases/download/x"));
        // Spellings a server would normalize out of the prefix.
        for escape in [
            "https://github.com/astral-sh/uv/releases/download/../../../other/x/releases/download/y",
            "https://github.com/astral-sh/uv/releases/download/./x",
            "https://github.com/astral-sh/uv/releases/download/%2e%2e/x",
            "https://github.com/astral-sh/uv/releases/download/..\\x",
            "https://github.com/astral-sh/uv/releases/download/a%2fb",
            "https://github.com/astral-sh/uv/releases/download/a%5Cb",
            "https://github.com/astral-sh/uv/releases/download/a%2",
            "https://github.com/astral-sh/uv/releases/download/a%zz",
            "https://github.com/astral-sh/uv/releases/download/a%25",
            "https://github.com/astral-sh/uv/releases/download/a%+5",
        ] {
            assert!(!endpoint.covers(escape), "{escape}");
        }
        // An escape that decodes to an ordinary character is inert.
        assert!(endpoint.covers(
            "https://github.com/astral-sh/uv/releases/download/cpython-3.12.14%2B20260825.tar.gz"
        ));
        let origin = Endpoint::new("https://nodejs.org").unwrap();
        assert!(origin.covers("https://nodejs.org/dist/v24.20.0/node.tar.gz"));
        assert!(!origin.covers("https://nodejs.org:8443/dist/x"));
        for bad in [
            "http://x/",
            "file:///tmp/x",
            "https://",
            "https://user@host/",
            "ftp://x",
        ] {
            assert!(Endpoint::new(bad).is_err(), "{bad:?} accepted");
        }
    }

    #[test]
    fn authorize_refuses_non_https_unknown_publishers_and_foreign_endpoints() {
        let policy = SourcePolicy::shipped();
        let ok = policy
            .authorize(
                "nodejs.org",
                "https://nodejs.org/dist/v24.20.0/node-v24.20.0-linux-x64.tar.gz",
            )
            .unwrap();
        assert_eq!(ok.publisher, "nodejs.org");
        assert!(ok.endpoint.credential.is_none());
        for (publisher, url, why) in [
            ("nodejs.org", "file:///tmp/node.tar.gz", "only https://"),
            (
                "nodejs.org",
                "http://nodejs.org/dist/x.tar.gz",
                "only https://",
            ),
            (
                "nodejs.org",
                "https://static.rust-lang.org/dist/x",
                "not under any endpoint",
            ),
            ("nobody", "https://nodejs.org/dist/x", "no such publisher"),
            (
                "uv",
                "https://github.com/astral-sh/python-build-standalone/releases/download/x",
                "not under any endpoint",
            ),
        ] {
            let error = policy.authorize(publisher, url).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            assert!(error.to_string().contains(why), "{url}: {error}");
        }
        assert!(SourcePolicy::empty()
            .authorize("nodejs.org", "https://nodejs.org/dist/x")
            .is_err());
    }

    #[test]
    fn redirects_get_the_target_endpoints_credential_or_none() {
        let mut policy = SourcePolicy::empty();
        policy
            .allow(
                "corp",
                Endpoint::with_credential("https://artifacts.corp.example/", "CORP_TOKEN").unwrap(),
            )
            .unwrap();
        policy
            .allow("corp", Endpoint::new("https://cdn.corp.example/").unwrap())
            .unwrap();
        let first = policy
            .authorize("corp", "https://artifacts.corp.example/node.tar.gz")
            .unwrap();
        assert_eq!(
            first.endpoint.credential.as_ref().unwrap().name,
            "CORP_TOKEN"
        );
        // A redirect is re-authorized under the same publisher: the CDN
        // endpoint carries no credential, so none is sent there.
        let redirected = policy
            .authorize("corp", "https://cdn.corp.example/blob/1")
            .unwrap();
        assert!(redirected.endpoint.credential.is_none());
        // A redirect off-policy refuses even though the first hop passed.
        assert!(policy
            .authorize("corp", "https://elsewhere.example/blob/1")
            .is_err());
        // Adding an endpoint is explicit and idempotent.
        policy
            .allow("corp", Endpoint::new("https://cdn.corp.example/").unwrap())
            .unwrap();
        assert_eq!(policy.publisher("corp").unwrap().endpoints.len(), 2);
        assert!(policy
            .allow("", Endpoint::new("https://x.example/").unwrap())
            .is_err());
        assert!(Endpoint::with_credential("https://x.example/", "").is_err());
    }

    #[test]
    fn shipped_github_publishers_admit_the_asset_cdn_hop() {
        let policy = SourcePolicy::shipped();
        // GitHub release downloads redirect to the asset CDN; the shipped
        // publisher admits that hop under the same publisher.
        let hop = policy
            .authorize(
                "uv",
                "https://objects.githubusercontent.com/github-production-release-asset/1",
            )
            .unwrap();
        assert_eq!(hop.publisher, "uv");
    }
}

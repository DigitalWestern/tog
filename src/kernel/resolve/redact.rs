//! Redaction: what a URL or a command line looks like once every credential
//! shape is gone. Everything the ledger and the resolution record carry
//! passes through here before it is serialized.
//!
//! - URL userinfo is removed.
//! - Every query value becomes `REDACTED`, keeping its key, except the keys
//!   a registry protocol declares as naming content. That covers presigned
//!   URL signatures (`X-Amz-Signature`, `X-Goog-Signature`, Azure `sig`,
//!   `token`, `key`) without listing them.
//! - A fragment survives only as a content digest (`#sha256=<hex>`).
//! - In a command line, URL-shaped operands are redacted as above, and the
//!   values of credential-bearing flags and settings become `REDACTED`: any
//!   flag or `key=value` whose name contains `token`, `auth`, `password`,
//!   `passwd`, `secret`, `credential`, or `extraheader` (git's header
//!   setting), and `-u`/`--user` when the value
//!   holds a `user:password` pair. Caller-named secrets (the session token,
//!   the proxy address) are replaced wherever they appear.
//!
//! Headers and the environment are never recorded, so they need no rule.

pub const REDACTED: &str = "REDACTED";

/// The words that make a flag or setting name credential-bearing.
/// `extraheader` is git's `http.extraHeader`, which carries whole
/// `Authorization` headers.
const SECRET_WORDS: &[&str] = &[
    "token",
    "auth",
    "password",
    "passwd",
    "secret",
    "credential",
    "extraheader",
];

fn names_a_secret(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    SECRET_WORDS.iter().any(|word| name.contains(word))
}

/// A fragment that is a content digest (`sha256=<hex>`, `md5=<hex>`).
fn digest_fragment(fragment: &str) -> bool {
    match fragment.split_once('=') {
        Some((algo, hex)) => {
            matches!(
                algo,
                "md5" | "sha1" | "sha224" | "sha256" | "sha384" | "sha512"
            ) && !hex.is_empty()
                && hex.bytes().all(|b| b.is_ascii_hexdigit())
        }
        None => false,
    }
}

/// Redact the query of a URL: each `key=value` keeps its key, and its value
/// only if `keep` names the key.
fn query(raw: &str, keep: &[&str]) -> String {
    raw.split('&')
        .map(|pair| match pair.split_once('=') {
            Some((key, _)) if keep.contains(&key) => pair.to_string(),
            Some((key, _)) => format!("{key}={REDACTED}"),
            None if pair.is_empty() || keep.contains(&pair) => pair.to_string(),
            // A bare token (`?abc123`) may itself be the secret.
            None => REDACTED.to_string(),
        })
        .collect::<Vec<_>>()
        .join("&")
}

/// Redact one URL (or a path with a query, for requests the proxy could not
/// attribute to an upstream). `keep` is the protocol's content query keys.
pub fn url(raw: &str, keep: &[&str]) -> String {
    let (rest, fragment) = match raw.split_once('#') {
        Some((rest, fragment)) => (rest, Some(fragment)),
        None => (raw, None),
    };
    let (base, raw_query) = match rest.split_once('?') {
        Some((base, q)) => (base, Some(q)),
        None => (rest, None),
    };
    let base = strip_userinfo(base);
    let mut out = base;
    if let Some(raw_query) = raw_query {
        out.push('?');
        out.push_str(&query(raw_query, keep));
    }
    if let Some(fragment) = fragment {
        out.push('#');
        out.push_str(if digest_fragment(fragment) {
            fragment
        } else {
            REDACTED
        });
    }
    out
}

/// `scheme://user:pw@host/...` without `user:pw@`. The authority ends at the
/// first `/` after the scheme; an `@` after that is part of the path (npm
/// scopes) and is kept.
fn strip_userinfo(base: &str) -> String {
    let Some((scheme, after)) = base.split_once("://") else {
        return base.to_string();
    };
    let authority_end = after.find('/').unwrap_or(after.len());
    let (authority, path) = after.split_at(authority_end);
    let host = match authority.rfind('@') {
        Some(at) => &authority[at + 1..],
        None => authority,
    };
    format!("{scheme}://{host}{path}")
}

/// Redact every URL embedded in `text` (a PEP 508 `name @ https://...`, a
/// `key=https://...`).
fn embedded_urls(text: &str) -> String {
    let mut out = String::new();
    let mut rest = text;
    while let Some(at) = rest.find("://") {
        // The scheme runs back from `://` over scheme characters.
        // The boundary character may be multi-byte (a Unicode space), so
        // step past it by its own length, not by one byte.
        let scheme_start = rest[..at]
            .char_indices()
            .rev()
            .find(|(_, c)| !(c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.')))
            .map_or(0, |(i, c)| i + c.len_utf8());
        let end = rest[at..]
            .find(char::is_whitespace)
            .map_or(rest.len(), |i| at + i);
        out.push_str(&rest[..scheme_start]);
        out.push_str(&url(&rest[scheme_start..end], &[]));
        rest = &rest[end..];
    }
    out.push_str(rest);
    out
}

/// What the operand after a flag is.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Next {
    Plain,
    /// The value of a credential flag (`--token x`).
    Secret,
    /// The value of `-u`/`--user`: a secret when it holds `user:password`.
    User,
}

/// Redact a command line: a tog verb's operands or a tool's argv.
/// `secrets` (the session token, the proxy address) are replaced wherever
/// they occur, after the other rules ran.
pub fn command(argv: &[String], secrets: &[&str]) -> Vec<String> {
    let mut out = Vec::with_capacity(argv.len());
    let mut next = Next::Plain;
    for operand in argv {
        let redacted = match next {
            Next::Secret => {
                next = Next::Plain;
                REDACTED.to_string()
            }
            Next::User if operand.contains(':') => {
                next = Next::Plain;
                REDACTED.to_string()
            }
            Next::User | Next::Plain => {
                let (text, following) = operand_rule(operand);
                next = following;
                text
            }
        };
        out.push(scrub(&redacted, secrets));
    }
    out
}

/// One operand under the flag rules, and what the operand after it is.
fn operand_rule(operand: &str) -> (String, Next) {
    if operand == "-u" || operand == "--user" {
        return (operand.to_string(), Next::User);
    }
    // `-uuser:pass`, `--user=user:pass`.
    if let Some(value) = operand
        .strip_prefix("--user=")
        .or_else(|| operand.strip_prefix("-u").filter(|v| !v.is_empty()))
    {
        if value.contains(':') {
            let flag = &operand[..operand.len() - value.len()];
            return (format!("{flag}{REDACTED}"), Next::Plain);
        }
    }
    if let Some(flag) = operand.strip_prefix('-') {
        let flag = flag.trim_start_matches('-');
        match flag.split_once('=') {
            // `--token=x`, `--config.auth=x`, `--_authToken=x`, and
            // `--config=registries.corp.token=x`.
            Some((name, value)) if names_a_secret(name) || setting_is_secret(value) => {
                let kept = &operand[..operand.len() - value.len()];
                return (format!("{kept}{REDACTED}"), Next::Plain);
            }
            // `--token x`: the next operand is the value. `--no-auth` and
            // friends are switches, not value flags.
            None if names_a_secret(flag) && !flag.starts_with("no-") => {
                return (operand.to_string(), Next::Secret)
            }
            _ => {}
        }
    }
    // A setting (`key=value`, npm's `//host/:_authToken=x`, the value of
    // `--config`/`-c`).
    if let Some((key, _)) = operand.split_once('=') {
        if !key.contains("://") && names_a_secret(key) {
            return (format!("{key}={REDACTED}"), Next::Plain);
        }
    }
    (embedded_urls(operand), Next::Plain)
}

/// `--config=key=value`'s value half, when the key is credential-bearing.
fn setting_is_secret(value: &str) -> bool {
    value
        .split_once('=')
        .is_some_and(|(key, _)| !key.contains("://") && names_a_secret(key))
}

fn scrub(text: &str, secrets: &[&str]) -> String {
    let mut out = embedded_urls(text);
    for secret in secrets {
        if !secret.is_empty() {
            out = out.replace(secret, REDACTED);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn redaction_removes_userinfo_secret_queries_and_credential_operands() {
        // URLs.
        assert_eq!(
            url("https://user:tok@registry.example/pkg/-/pkg-1.0.0.tgz", &[]),
            "https://registry.example/pkg/-/pkg-1.0.0.tgz"
        );
        assert_eq!(
            url("https://registry.npmjs.org/@scope%2fname", &[]),
            "https://registry.npmjs.org/@scope%2fname"
        );
        assert_eq!(
            url(
                "https://bucket.s3.amazonaws.com/a.whl?X-Amz-Signature=abc&X-Amz-Credential=AK%2F1&format=json",
                &["format"]
            ),
            "https://bucket.s3.amazonaws.com/a.whl?X-Amz-Signature=REDACTED&X-Amz-Credential=REDACTED&format=json"
        );
        assert_eq!(
            url("https://h/x?sig=s&se=2030&sp=r&token=t&key=k&bare", &[]),
            "https://h/x?sig=REDACTED&se=REDACTED&sp=REDACTED&token=REDACTED&key=REDACTED&REDACTED"
        );
        assert_eq!(
            url("https://h/a.whl#sha256=0a1b", &[]),
            "https://h/a.whl#sha256=0a1b"
        );
        assert_eq!(
            url("https://h/a#access_token=zzz", &[]),
            "https://h/a#REDACTED"
        );
        assert_eq!(
            url("/f00d/fixture/meta?auth=x", &[]),
            "/f00d/fixture/meta?auth=REDACTED"
        );

        // Command operands.
        let token = "4f6b0c1d2e3f";
        let got = command(
            &argv(&[
                "install",
                "--registry=https://ci:hunter2@npm.example/",
                "--password",
                "hunter2",
                "--token=abc",
                "--_authToken=xyz",
                "//registry.npmjs.org/:_authToken=npm_ABC",
                "-u",
                "alice:hunter2",
                "-ualice:hunter2",
                "--user=alice:hunter2",
                "--config",
                "http.extraHeader=x",
                "--config",
                "registries.corp.token=secret",
                "--config.auth-type=legacy",
                "--no-auth",
                "requests @ https://u:p@files.example/r.whl#sha256=00ff",
                "--proxy",
                &format!("http://tog:{token}@127.0.0.1:8119"),
                "-c",
                "credential.helper=store",
            ]),
            &[token, "127.0.0.1:8119"],
        );
        assert_eq!(
            got,
            argv(&[
                "install",
                "--registry=https://npm.example/",
                "--password",
                "REDACTED",
                "--token=REDACTED",
                "--_authToken=REDACTED",
                "//registry.npmjs.org/:_authToken=REDACTED",
                "-u",
                "REDACTED",
                "-uREDACTED",
                "--user=REDACTED",
                "--config",
                "http.extraHeader=REDACTED",
                "--config",
                "registries.corp.token=REDACTED",
                "--config.auth-type=REDACTED",
                "--no-auth",
                "requests @ https://files.example/r.whl#sha256=00ff",
                "--proxy",
                "http://REDACTED",
                "-c",
                "credential.helper=REDACTED",
            ])
        );
    }

    /// A golden over a corpus of the secret shapes tools actually carry: no
    /// secret text survives into ledger bytes, and the redacted forms are
    /// exactly these.
    #[test]
    fn no_known_secret_shape_survives_in_a_ledger() {
        use crate::kernel::resolve::ledger::{Entry, PortableLedger};
        const SECRETS: &[&str] = &[
            "hunter2",
            "npm_Q7fz3kSecretToken",
            "ghp_16C7e42F292c6912E7710c838347Ae178B4a",
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI%2FK7MDENG",
            "sv%3D2024-sig-9f8e",
            "GOOG1EXAMPLESIGNATURE",
            "0123456789abcdef-session-token",
            "glpat-xxxxxxxxxxxxxxxxxxxx",
        ];
        let urls = [
            "https://ci:hunter2@registry.npmjs.org/pkg/-/pkg-1.0.0.tgz",
            "https://oauth2:glpat-xxxxxxxxxxxxxxxxxxxx@gitlab.example/pkg.git",
            "https://bucket.s3.amazonaws.com/f.whl?X-Amz-Algorithm=AWS4-HMAC-SHA256\
             &X-Amz-Credential=AKIAIOSFODNN7EXAMPLE&X-Amz-Signature=wJalrXUtnFEMI%2FK7MDENG",
            "https://acct.blob.core.windows.net/c/f.tgz?sv=2024&sig=sv%3D2024-sig-9f8e&se=2030",
            "https://storage.googleapis.com/b/f.zip?X-Goog-Signature=GOOG1EXAMPLESIGNATURE",
            "https://api.github.com/repos/o/r/tarball?access_token=ghp_16C7e42F292c6912E7710c838347Ae178B4a",
            "https://files.pythonhosted.org/p/f.whl#sha256=00ff",
        ];
        let mut ledger = PortableLedger::new("fixture", "edit").unwrap();
        for url in urls {
            ledger.insert(Entry {
                class: "artifact".into(),
                method: "GET".into(),
                url: super::url(url, &["format"]),
                status: 200,
                sha256: None,
                claimed: None,
                verified: false,
                freshness: None,
            });
        }
        let argv = command(
            &argv(&[
                "npm",
                "install",
                "//registry.npmjs.org/:_authToken=npm_Q7fz3kSecretToken",
                "--password=hunter2",
                "-u",
                "ci:hunter2",
                "--config",
                "http.extraHeader=Authorization: Bearer ghp_16C7e42F292c6912E7710c838347Ae178B4a",
                "--proxy=http://tog:0123456789abcdef-session-token@127.0.0.1:41000",
            ]),
            &["0123456789abcdef-session-token", "127.0.0.1:41000"],
        );
        let mut text = String::from_utf8(ledger.bytes()).unwrap();
        text.push_str(&argv.join(" "));
        for secret in SECRETS {
            assert!(!text.contains(secret), "{secret} survived:\n{text}");
        }
        let urls: Vec<&str> = ledger.entries().map(|entry| entry.url.as_str()).collect();
        assert_eq!(
            urls,
            [
                "https://acct.blob.core.windows.net/c/f.tgz?sv=REDACTED&sig=REDACTED&se=REDACTED",
                "https://api.github.com/repos/o/r/tarball?access_token=REDACTED",
                "https://bucket.s3.amazonaws.com/f.whl?X-Amz-Algorithm=REDACTED\
                 &X-Amz-Credential=REDACTED&X-Amz-Signature=REDACTED",
                "https://files.pythonhosted.org/p/f.whl#sha256=00ff",
                "https://gitlab.example/pkg.git",
                "https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz",
                "https://storage.googleapis.com/b/f.zip?X-Goog-Signature=REDACTED",
            ]
        );
        assert_eq!(
            argv.join(" "),
            "npm install //registry.npmjs.org/:_authToken=REDACTED --password=REDACTED -u \
             REDACTED --config http.extraHeader=REDACTED --proxy=http://REDACTED"
        );
    }

    #[test]
    fn a_unicode_space_before_a_url_is_a_boundary_not_a_crash() {
        for space in ["\u{a0}", "\u{3000}", "\u{2003}", "\u{85}", "é"] {
            let operand = format!("dep{space}https://u:p@host.example/x?token=t");
            let got = command(&[operand], &[]);
            assert_eq!(
                got,
                [format!("dep{space}https://host.example/x?token=REDACTED")]
            );
        }
    }

    /// Property-style: random operands built from URL fragments, secret
    /// shapes, and mixed Unicode and whitespace never panic the redactor,
    /// and never keep a password that sat in userinfo.
    #[test]
    fn the_redactor_never_panics_on_mixed_unicode_and_whitespace() {
        const PIECES: &[&str] = &[
            "https://",
            "http://",
            "git+ssh://",
            "://",
            "u:hunter2@",
            "@",
            "/",
            "?",
            "#",
            "=",
            "&",
            ":",
            "-",
            "--",
            "-u",
            "token",
            "auth",
            "a",
            "Z9",
            "%2F",
            "%",
            " ",
            "\t",
            "\u{a0}",
            "\u{3000}",
            "\u{2028}",
            "\u{85}",
            "é",
            "ß",
            "漢字",
            "🦀",
            "\u{200b}",
            "\u{feff}",
            "sha256=00ff",
            "=https://x@y/",
            "\n",
            "\r",
        ];
        // xorshift: deterministic, so a failure reproduces.
        let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..20_000 {
            let operands: Vec<String> = (0..1 + next() % 4)
                .map(|_| {
                    (0..next() % 12)
                        .map(|_| PIECES[(next() % PIECES.len() as u64) as usize])
                        .collect()
                })
                .collect();
            let redacted = command(&operands, &["hunter2"]);
            assert!(
                redacted.iter().all(|operand| !operand.contains("hunter2")),
                "{operands:?}"
            );
            for operand in &operands {
                let _ = url(operand, &["format"]);
            }
        }
    }
}

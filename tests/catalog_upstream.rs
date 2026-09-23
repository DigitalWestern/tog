//! The shipped toolchain catalogs, re-verified against upstream. Network:
//! run with `cargo test --test catalog_upstream -- --ignored`.
//!
//! `tools/catalog.py` verifies every row when it generates a catalog. This
//! test re-checks a sample of each (the default, the newest and the oldest
//! release) against the checksum each upstream publishes, independently of
//! the generator: a row edited by hand, or an upstream that re-published an
//! archive under the same name, fails here. Where an upstream publishes no
//! checksum listing (Homebrew portable-ruby and erlef's OTP builds, whose
//! only published digest is GitHub's asset metadata), the archive is
//! downloaded and hashed.

use std::collections::BTreeMap;
use std::io::Read;

use sha2::{Digest as _, Sha256, Sha512};
use tog::kernel::toolchain::{ArtifactRow, Bundle};

fn get(url: &str) -> Vec<u8> {
    let response = ureq::get(url)
        .call()
        .unwrap_or_else(|e| panic!("GET {url}: {e}"));
    let mut body = Vec::new();
    response
        .into_reader()
        .read_to_end(&mut body)
        .unwrap_or_else(|e| panic!("GET {url}: {e}"));
    body
}

fn get_text(url: &str) -> String {
    String::from_utf8(get(url)).unwrap_or_else(|e| panic!("GET {url}: {e}"))
}

/// Upstream answers, fetched once per test run.
#[derive(Default)]
struct Upstream {
    texts: BTreeMap<String, String>,
    json: BTreeMap<String, serde_json::Value>,
    hashed: BTreeMap<String, String>,
}

impl Upstream {
    fn text(&mut self, url: &str) -> &str {
        self.texts
            .entry(url.to_string())
            .or_insert_with(|| get_text(url))
    }

    fn json(&mut self, url: &str) -> &serde_json::Value {
        self.json.entry(url.to_string()).or_insert_with(|| {
            serde_json::from_str(&get_text(url)).unwrap_or_else(|e| panic!("{url}: {e}"))
        })
    }

    /// The archive itself, downloaded and hashed with the row's algorithm.
    fn downloaded(&mut self, row: &ArtifactRow) -> String {
        let algo = row.digest.algo();
        self.hashed
            .entry(row.url.clone())
            .or_insert_with(|| {
                let body = get(&row.url);
                let hex = match algo {
                    "sha512" => hex::encode(Sha512::digest(&body)),
                    _ => hex::encode(Sha256::digest(&body)),
                };
                format!("{algo}:{hex}")
            })
            .clone()
    }

    /// The digest upstream publishes for this row's archive, qualified with
    /// its algorithm, and where it was read.
    fn published(&mut self, row: &ArtifactRow) -> (String, String) {
        let url = row.url.as_str();
        let (dir, name) = url.rsplit_once('/').unwrap();
        let name = name.replace("%2B", "+");
        if url.starts_with("https://go.dev/dl/") {
            let source = "https://go.dev/dl/?mode=json&include=all";
            let files = self.json(source).as_array().unwrap();
            let file = files
                .iter()
                .flat_map(|release| release["files"].as_array().unwrap())
                .find(|file| file["filename"] == name.as_str())
                .unwrap_or_else(|| panic!("{source} lists no {name}"));
            let sha = file["sha256"].as_str().unwrap();
            return (format!("sha256:{sha}"), source.to_string());
        }
        if url.starts_with("https://nodejs.org/dist/")
            || url.contains("/astral-sh/python-build-standalone/releases/download/")
        {
            let listing = if url.starts_with("https://nodejs.org/") {
                "SHASUMS256.txt"
            } else {
                "SHA256SUMS"
            };
            let source = format!("{dir}/{listing}");
            return (listed(self.text(&source), &name, &source), source);
        }
        if url.contains("/astral-sh/uv/releases/download/")
            || url.contains("/DigitalWestern/tog-toolchains/releases/download/")
        {
            let source = format!("{url}.sha256");
            return (side_file("sha256", self.text(&source)), source);
        }
        if url.contains("/elixir-lang/elixir/releases/download/") {
            let source = format!("{url}.sha256sum");
            return (side_file("sha256", self.text(&source)), source);
        }
        if let Some(path) = url.strip_prefix("https://builds.hex.pm/installs/") {
            // installs/<elixir dir>/<tool>-<version>-otp-<otp>[.ez], listed
            // in hex.csv or rebar.csv as `version,sha512,elixir dir,otp`.
            let (elixir_dir, file) = path.split_once('/').unwrap();
            let (tool, rest) = file.split_once('-').unwrap();
            let (version, otp) = rest.trim_end_matches(".ez").split_once("-otp-").unwrap();
            let listing = if tool == "rebar3" { "rebar" } else { tool };
            let source = format!("https://builds.hex.pm/installs/{listing}.csv");
            let sha = self
                .text(&source)
                .lines()
                .map(|line| line.split(',').collect::<Vec<_>>())
                .find(|fields| {
                    fields.len() >= 4
                        && fields[0] == version
                        && fields[2] == elixir_dir
                        && fields[3] == otp
                })
                .unwrap_or_else(|| panic!("{source} lists no {file}"))[1]
                .to_string();
            return (format!("sha512:{sha}"), source);
        }
        if url.starts_with("https://builds.dotnet.microsoft.com/dotnet/") {
            let channel = row.build.split('.').take(2).collect::<Vec<_>>().join(".");
            let source = format!(
                "https://builds.dotnet.microsoft.com/dotnet/release-metadata/{channel}/releases.json"
            );
            let releases = self.json(&source)["releases"].as_array().unwrap();
            let hash = releases
                .iter()
                .flat_map(|release| release["sdks"].as_array().into_iter().flatten())
                .flat_map(|sdk| sdk["files"].as_array().unwrap())
                .find(|file| file["url"] == url)
                .unwrap_or_else(|| panic!("{source} lists no {url}"))["hash"]
                .as_str()
                .unwrap()
                .to_lowercase();
            return (format!("sha512:{hash}"), source);
        }
        if url.contains("/Homebrew/homebrew-portable-ruby/releases/download/")
            || url.contains("/erlef/otp_builds/releases/download/")
        {
            return (self.downloaded(row), url.to_string());
        }
        panic!("no upstream checksum source is known for {url}");
    }
}

/// `<hex>  <name>` lines, as `sha256sum` writes them.
fn listed(listing: &str, name: &str, source: &str) -> String {
    listing
        .lines()
        .filter_map(|line| line.split_once(char::is_whitespace))
        .find(|(_, file)| file.trim().trim_start_matches('*') == name)
        .map(|(sha, _)| format!("sha256:{}", sha.to_lowercase()))
        .unwrap_or_else(|| panic!("{source} lists no {name}"))
}

/// A side file holding one digest, optionally followed by the file name.
fn side_file(algo: &str, text: &str) -> String {
    format!(
        "{algo}:{}",
        text.split_whitespace().next().unwrap().to_lowercase()
    )
}

/// The default, the newest and the oldest release of a catalog.
fn samples(ecosystem: &str) -> Vec<Bundle> {
    let catalog = tog::tailors::by_id(ecosystem)
        .unwrap()
        .toolchain_catalog()
        .unwrap();
    let bundles = catalog.bundles();
    let mut samples = vec![catalog.default_release().unwrap().clone()];
    for bundle in [bundles.first().unwrap(), bundles.last().unwrap()] {
        if samples.iter().all(|s| s.release != bundle.release) {
            samples.push(bundle.clone());
        }
    }
    samples
}

fn verify(ecosystem: &str) {
    let mut upstream = Upstream::default();
    let mut checked = 0;
    for bundle in samples(ecosystem) {
        for row in &bundle.artifacts {
            let (published, source) = upstream.published(row);
            let shipped = tog::kernel::toolchain::qualified(&row.digest);
            assert_eq!(
                shipped,
                published,
                "{ecosystem} {} {} {}: the shipped digest is not what {source} publishes",
                bundle.release,
                row.platform.triple(),
                row.component
            );
            checked += 1;
        }
    }
    assert!(checked > 0);
    eprintln!("{ecosystem}: {checked} rows match upstream");
}

#[test]
#[ignore = "network: fetches upstream checksum listings"]
fn go_rows_match_upstream() {
    verify("go");
}

#[test]
#[ignore = "network: fetches upstream checksum listings"]
fn node_rows_match_upstream() {
    verify("node");
}

#[test]
#[ignore = "network: fetches upstream checksum listings"]
fn python_rows_match_upstream() {
    verify("python");
}

#[test]
#[ignore = "network: downloads the sampled portable-ruby bottles"]
fn ruby_rows_match_upstream() {
    verify("ruby");
}

#[test]
#[ignore = "network: fetches checksum listings and downloads erlef's OTP build"]
fn elixir_rows_match_upstream() {
    verify("elixir");
}

#[test]
#[ignore = "network: fetches the .NET release metadata"]
fn dotnet_rows_match_upstream() {
    verify("dotnet");
}

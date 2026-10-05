//! Observe the requests made by the actual pinned npm during resolution.
#![allow(clippy::disallowed_methods)]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::thread;
use std::time::Duration;

mod common;
use common::{assert_ok, command, TempDir};

struct Registry {
    url: String,
    requests: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}

impl Registry {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        listener.set_nonblocking(true).unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let recorded = requests.clone();
        let finished = stop.clone();
        let metadata = serde_json::json!({
            "name": "is-number",
            "dist-tags": {"latest": "1.0.0"},
            "versions": {"1.0.0": {
                "name": "is-number", "version": "1.0.0",
                "dist": {
                    "tarball": format!("{url}/is-number-1.0.0.tgz"),
                    "integrity": format!("sha512-{}==", "A".repeat(86)),
                },
            }},
        })
        .to_string();
        let worker = thread::spawn(move || {
            while !finished.load(Ordering::Relaxed) {
                let (mut stream, _) = match listener.accept() {
                    Ok(connection) => connection,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(error) => panic!("registry accept: {error}"),
                };
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut request = Vec::new();
                let mut buffer = [0; 4096];
                while !request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                    match stream.read(&mut buffer) {
                        Ok(0) | Err(_) => break,
                        Ok(count) => request.extend_from_slice(&buffer[..count]),
                    }
                }
                let line = String::from_utf8_lossy(&request)
                    .lines()
                    .next()
                    .unwrap_or("")
                    .to_string();
                let parts: Vec<_> = line.split_whitespace().collect();
                if parts.len() < 2 {
                    continue;
                }
                recorded
                    .lock()
                    .unwrap()
                    .push(format!("{} {}", parts[0], parts[1]));
                let body = if parts[0] == "GET" && parts[1] == "/is-number" {
                    metadata.as_str()
                } else {
                    "{}"
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len(),
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });
        Self {
            url,
            requests,
            stop,
            worker: Some(worker),
        }
    }
}

impl Drop for Registry {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.worker.take().unwrap().join().unwrap();
    }
}

#[test]
#[ignore]
fn npm_resolution_makes_only_the_required_package_metadata_request() {
    let registry = Registry::start();
    let temp = TempDir::new("npm-quiet-requests");
    let project = &temp.0;
    let home = project.join("home");
    std::fs::create_dir(&home).unwrap();
    std::fs::write(
        project.join("package.json"),
        r#"{"name":"quiet-fixture","version":"1.0.0","dependencies":{"is-number":"1.0.0"}}"#,
    )
    .unwrap();
    // The command must override project settings as well as npm defaults.
    std::fs::write(
        project.join(".npmrc"),
        format!(
            "registry={}\nfetch-retries=0\naudit=true\nfund=true\nupdate-notifier=true\n",
            registry.url,
        ),
    )
    .unwrap();
    let probe = project.join("child-config-probe.cjs");
    // Run inside the actual delegated npm, using its inherited environment
    // and its own configuration and Git-fetcher modules. Exercise npm's
    // environment rewriting, then the configuration of the child npm that
    // pacote starts for a hosted Git dependency. No Git fetch is needed.
    std::fs::write(
        &probe,
        r#"
const fs = require('fs');
const path = require('path');
const cli = fs.realpathSync(process.argv[1]);
if (cli.endsWith('/npm-cli.js')) {
  const npmPath = path.dirname(path.dirname(cli));
  const Config = require(npmPath + '/node_modules/@npmcli/config');
  const defs = require(npmPath + '/node_modules/@npmcli/config/lib/definitions');
  const setEnvs = require(npmPath + '/node_modules/@npmcli/config/lib/set-envs.js');
  const GitFetcher = require(npmPath + '/node_modules/pacote/lib/git.js');
  const env = {...process.env};
  function configFor(args, inherited) {
    const c = new Config({...defs, npmPath, argv: ['node', 'npm', ...args],
                          env: inherited, cwd: process.cwd()});
    c.loadDefaults(); c.loadCLI(); c.loadEnv();
    return c;
  }
  const parent = configFor(process.argv.slice(2), env);
  setEnvs(parent);
  const git = new GitFetcher(
    'github:example/pkg#0123456789012345678901234567890123456789',
    {cache: process.cwd(), npmBin: cli});
  const child = configFor([...git.npmInstallCmd, ...git.npmCliConfig], {...env});
  const data = child.data.get('cli').data;
  for (const key of ['audit', 'fund', 'update-notifier']) {
    if (data[key] !== false) throw Error('child npm re-enabled ' + key);
  }
  fs.writeFileSync('child-config-checked', 'passed');
}
"#,
    )
    .unwrap();
    assert_ok(
        command(project, &home, &project.join("store"))
            .env("NODE_OPTIONS", format!("--require={}", probe.display()))
            .env("npm_config_audit", "true")
            .env("NPM_CONFIG_FUND", "true")
            .env("nPm_cOnFiG_uPdAtE_nOtIfIeR", "true")
            .args(["update", "--no-sync"])
            .output()
            .unwrap(),
        "npm resolution",
    );
    let lock = std::fs::read_to_string(project.join("package-lock.json")).unwrap();
    assert!(lock.contains("is-number-1.0.0.tgz"), "{lock}");
    let requests = registry.requests.lock().unwrap().clone();
    assert_eq!(requests, ["GET /is-number"], "npm made unrelated requests");
    assert_eq!(
        std::fs::read_to_string(project.join("child-config-checked")).unwrap(),
        "passed"
    );
    assert!(!project.join("node_modules").exists());
}

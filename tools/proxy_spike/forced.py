"""Forced program settings, proven with marker programs (PR 0 of §6).

Fixtures live in tests/fixtures/proxy/forced/<tool>/. Each has a
settings.json naming the settings that make the tool run a program. For
each setting, a control run applies it with today's census invocation and
records whether its marker ran; the forced run applies every setting at once
with the door's forced flags and records that no marker ran. Every run is
confined the same way as the census (see spike.py). Results go to
WORK/forced.jsonl and to claims.jsonl.
"""

import json
import os
import re
import shutil
import stat
import subprocess

import spike

FIXTURES = os.path.join(spike.REPO, "tests", "fixtures", "proxy", "forced")


class Fixture:
    def __init__(self, session, fixture, label, settings_filter=None):
        self.s = session
        self.src = os.path.join(FIXTURES, fixture)
        self.meta = json.load(open(os.path.join(self.src, "settings.json")))
        self.dir = session.scenario_dir(label)
        self.hit = os.path.join(self.dir, ".spike", "markers", "hit")
        self.bin = os.path.join(self.dir, ".spike", "markers", "bin")
        self.path_bin = os.path.join(self.dir, ".spike", "markers", "path")
        for path in (self.hit, self.bin, self.path_bin):
            os.makedirs(path, exist_ok=True)
        self.extra = {}
        for root, _, files in os.walk(self.src):
            for name in files:
                if name == "settings.json":
                    continue
                source = os.path.join(root, name)
                rel = os.path.relpath(source, self.src)
                target = os.path.join(self.dir, rel)
                os.makedirs(os.path.dirname(target), exist_ok=True)
                with open(target, "w") as handle:
                    handle.write(self.sub(open(source).read()))
        for rel, content in self.meta.get("extra_files", {}).items():
            with open(os.path.join(self.dir, rel), "w") as handle:
                handle.write(self.sub(content))

    def marker(self, name, kind="sh"):
        safe = re.sub(r"[^A-Za-z0-9_.-]", "_", name)
        hit = os.path.join(self.hit, name)
        if kind == "js":
            path = os.path.join(self.bin, safe + ".cjs")
            body = f"require('fs').writeFileSync({json.dumps(hit)}, '');\n"
        else:
            path = os.path.join(self.bin, safe)
            body = f"#!/bin/sh\n: > '{hit}'\nexit 1\n"
        with open(path, "w") as handle:
            handle.write(body)
        os.chmod(path, 0o755)
        return path

    def path_marker(self, command, name):
        path = os.path.join(self.path_bin, command)
        with open(path, "w") as handle:
            handle.write(f"#!/bin/sh\n: > '{os.path.join(self.hit, name)}'\nexit 1\n")
        os.chmod(path, 0o755)

    def sub(self, text):
        text = re.sub(r"@M:([^@]+)@", lambda m: self.marker(m.group(1)), text)
        text = re.sub(r"@J:([^@]+)@", lambda m: self.marker(m.group(1), "js"), text)
        replacements = {
            "@HIT@": self.hit,
            "@SCENARIO@": self.dir,
            "@MIRROR@": self.s.mirror("").rstrip("/"),
            "@TOKEN@": self.s.token,
        }
        for key, value in replacements.items():
            text = text.replace(key, value)
        return text

    def hits(self):
        return sorted(os.listdir(self.hit))

    def clear(self):
        for name in os.listdir(self.hit):
            os.remove(os.path.join(self.hit, name))


def record(s, tool, rows, forced_hits, forced_rc, note=""):
    entry = {"tool": tool, "controls": rows, "forced_hits": forced_hits, "forced_rc": forced_rc, "note": note}
    with open(os.path.join(s.work, "forced.jsonl"), "a") as handle:
        handle.write(json.dumps(entry) + "\n")
    s.claim(f"forced-{tool}", "confirmed" if not [h for h in forced_hits if not h.startswith("by-design:")] else "refuted",
            f"controls {rows}; forced run rc={forced_rc} hits={forced_hits} {note}")


def host_git(cwd, *args):
    env = {"PATH": "/usr/bin:/bin", "HOME": cwd, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
           "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid"}
    subprocess.run(["git"] + list(args), cwd=cwd, env=env, check=True, capture_output=True)


def make_repo(path, files_from):
    os.makedirs(path, exist_ok=True)
    for name in os.listdir(files_from):
        shutil.copy(os.path.join(files_from, name), os.path.join(path, name))
    host_git(path, "init", "-q", "-b", "main")
    host_git(path, "add", "-A")
    host_git(path, "commit", "-q", "-m", "fixture")


# ---------------------------------------------------------------------------


def forced_npm(s, pnpm=False):
    node, pnpm_bin = spike.node_paths(s)
    tool = "pnpm" if pnpm else "npm"
    meta_fixture = Fixture(s, tool, f"forced-{tool}-meta")
    settings = meta_fixture.meta["settings"]

    def run(fx, label, lines, forced):
        with open(os.path.join(fx.dir, ".npmrc"), "w") as handle:
            handle.write("".join(fx.sub(line) + "\n" for line in lines))
        make_repo(os.path.join(fx.dir, "prepdep.repo"), os.path.join(fx.dir, "prepdep"))
        env = s.base_env(fx.dir, [os.path.join(node, "bin")] + ([os.path.dirname(pnpm_bin)] if pnpm else []))
        env.update(spike.git_env(s))
        env["NODE_EXTRA_CA_CERTS"] = s.ca
        if pnpm:
            home = os.path.join(fx.dir, ".spike", "home")
            env.update({"XDG_CONFIG_HOME": home + "/xdg-config", "XDG_DATA_HOME": home + "/xdg-data",
                        "XDG_CACHE_HOME": home + "/xdg-cache", "XDG_STATE_HOME": home + "/xdg-state",
                        "CI": "1", "npm_config_ignore_scripts": "true"})
            spike_dir = os.path.join(fx.dir, ".spike")
            argv = [pnpm_bin, "install", "--lockfile-only", "--ignore-scripts", "--reporter", "append-only",
                    "--config.enable-modules-dir=false", "--config.node-linker=isolated",
                    f"--config.modules-dir={spike_dir}/modules", f"--config.virtual-store-dir={spike_dir}/vstore",
                    f"--config.store-dir={spike_dir}/store", f"--config.proxy={s.proxy_url}",
                    f"--config.https-proxy={s.proxy_url}", "--config.noproxy=", f"--config.cafile={s.ca}"]
        else:
            env["npm_config_cache"] = os.path.join(fx.dir, ".spike", "cache", "npm")
            argv = [os.path.join(node, "bin", "npm"), "--silent", "install", "--package-lock-only",
                    "--ignore-scripts", f"--proxy={s.proxy_url}", f"--https-proxy={s.proxy_url}", "--noproxy=",
                    "--registry=https://registry.npmjs.org/", f"--cafile={s.ca}", "--update-notifier=false"]
        if forced:
            argv += fx.meta["forced_flags"]
        return s.run(label, argv, env, fx.dir, fx.dir, timeout=180)

    rows = {}
    for setting in settings:
        fx = Fixture(s, tool, f"forced-{tool}-control-{setting['name']}")
        r = run(fx, f"forced-{tool}-control-{setting['name']}", [setting["line"]], forced=False)
        rows[setting["name"]] = {"hits": fx.hits(), "rc": r["rc"]}
    by_design = []
    for item in meta_fixture.meta.get("by_design", []):
        fx = Fixture(s, tool, f"forced-{tool}-by-design-{item['name']}")
        with open(os.path.join(fx.dir, item["file"]), "w") as handle:
            handle.write(fx.sub(item["content"]))
        r = run(fx, f"forced-{tool}-by-design-{item['name']}", [], forced=True)
        by_design += [f"by-design:{h}" for h in fx.hits()]
        rows[item["name"] + " (by design, forced run)"] = {"hits": fx.hits(), "rc": r["rc"]}
    fx = Fixture(s, tool, f"forced-{tool}-forced")
    r = run(fx, f"forced-{tool}-forced", [x["line"] for x in settings], forced=True)
    record(s, tool, rows, fx.hits() + by_design, r["rc"])


def forced_pnpm(s):
    forced_npm(s, pnpm=True)


def forced_cargo(s):
    rust = s.obj("*-rust-*")
    cargo = os.path.join(rust, "bin", "cargo")
    meta = Fixture(s, "cargo", "forced-cargo-meta").meta

    def run(fx, label, settings, forced):
        os.makedirs(os.path.join(fx.dir, ".cargo"), exist_ok=True)
        lines = [meta["base_config"]] + [x["line"] for x in settings]
        with open(os.path.join(fx.dir, ".cargo", "config.toml"), "w") as handle:
            handle.write("".join(fx.sub(line) + "\n" for line in lines))
        appends = "".join(x.get("manifest_append", "") for x in settings)
        if appends:
            with open(os.path.join(fx.dir, "Cargo.toml"), "a") as handle:
                handle.write(appends)
        env = s.base_env(fx.dir, [os.path.join(rust, "bin")])
        env.update({"CARGO_HOME": os.path.join(fx.dir, ".spike", "cargo-home"), "CARGO_NET_OFFLINE": "false"})
        env.update(spike.git_env(s))
        base = [cargo, "--config", f"http.proxy=\"{s.proxy_url}\"", "--config", f"http.cainfo=\"{s.ca}\"",
                "--config", "net.git-fetch-with-cli=true"]
        if forced:
            base += [flag.replace("@RUST@", rust) for flag in meta["forced_flags"]]
        results = [s.run(label + "-generate-lockfile", base + ["generate-lockfile"], env, fx.dir, fx.dir),
                   s.run(label + "-metadata", base + ["metadata", "--format-version", "1"], env, fx.dir, fx.dir)]
        return [x["rc"] for x in results]

    rows = {}
    for setting in meta["settings"]:
        fx = Fixture(s, "cargo", f"forced-cargo-control-{setting['name']}")
        rc = run(fx, f"forced-cargo-control-{setting['name']}", [setting], forced=False)
        rows[setting["name"]] = {"hits": fx.hits(), "rc": rc}
    fx = Fixture(s, "cargo", "forced-cargo-forced")
    rc = run(fx, "forced-cargo-forced", meta["settings"], forced=True)
    hits = fx.hits()
    fx2 = Fixture(s, "cargo", "forced-cargo-forced-no-evil-dep")
    rc2 = run(fx2, "forced-cargo-forced-no-evil-dep",
              [dict(x, manifest_append="") for x in meta["settings"]], forced=True)
    record(s, "cargo", rows, hits + fx2.hits(), rc,
           f"(with the auth-required dependency rc={rc}: cargo:token has no token; without it rc={rc2})")


def forced_uv(s):
    uv = os.path.join(s.obj("*-uv-*"), "uv")
    python = os.path.join(s.obj("*-cpython-*"), "bin", "python3")
    version = re.search(r"cpython-(\d+\.\d+)", s.obj("*-cpython-*")).group(1)
    meta = Fixture(s, "uv", "forced-uv-meta").meta

    def run(fx, label, settings, forced):
        sections = {"tool.uv": [], "tool.uv.pip": []}
        for setting in settings:
            if "file" in setting:
                with open(os.path.join(fx.dir, setting["file"]), "w") as handle:
                    handle.write(fx.sub(setting["content"]))
            else:
                sections[setting["section"]].append(fx.sub(setting["line"]))
            if "path_marker" in setting:
                fx.path_marker(setting["path_marker"], setting["name"])
        path = os.path.join(fx.dir, "pyproject.toml")
        text = open(path).read()
        for section, lines in sections.items():
            text = text.replace(f"@SETTINGS:{section}@", "\n".join(lines))
        with open(path, "w") as handle:
            handle.write(text)
        env = s.base_env(fx.dir, [fx.path_bin, os.path.dirname(uv)])
        env.update({"UV_PYTHON_DOWNLOADS": "never", "UV_CACHE_DIR": os.path.join(fx.dir, ".spike", "cache", "uv"),
                    "HTTPS_PROXY": s.proxy_url, "HTTP_PROXY": s.proxy_url, "NO_PROXY": "", "SSL_CERT_FILE": s.ca})
        forced_flags = [f.replace("@PYTHON@", python) for f in meta["forced_flags"]] if forced else []
        lock_env = dict(env, UV_PYTHON=python)
        a = s.run(label + "-lock", [uv, "lock", "--default-index", "https://pypi.org/simple"] + forced_flags,
                  lock_env, fx.dir, fx.dir)
        b = s.run(label + "-pip-compile", [uv, "pip", "compile", "requirements.in", "--generate-hashes",
                                           "--python-version", version, "--index-url", "https://pypi.org/simple",
                                           "-o", "requirements.lock.txt"] + forced_flags, env, fx.dir, fx.dir)
        return [a["rc"], b["rc"]]

    rows = {}
    for setting in meta["settings"]:
        fx = Fixture(s, "uv", f"forced-uv-control-{setting['name']}")
        rc = run(fx, f"forced-uv-control-{setting['name']}", [setting], forced=False)
        rows[setting["name"]] = {"hits": fx.hits(), "rc": rc}
    # What --no-config alone does to the project's [tool.uv] table.
    keyring = [x for x in meta["settings"] if x["name"] == "keyring-provider"]
    fx = Fixture(s, "uv", "forced-uv-no-config-only")
    saved = meta["forced_flags"]
    meta["forced_flags"] = ["--no-config"]
    rc = run(fx, "forced-uv-no-config-only", keyring, forced=True)
    meta["forced_flags"] = saved
    rows["keyring-provider with --no-config only"] = {"hits": fx.hits(), "rc": rc}
    fx = Fixture(s, "uv", "forced-uv-forced")
    rc = run(fx, "forced-uv-forced", meta["settings"], forced=True)
    record(s, "uv", rows, fx.hits(), rc)


def forced_git(s):
    git = shutil.which("git") or "/usr/bin/git"
    fx = Fixture(s, "vcs", "forced-git")
    meta = fx.meta
    hooks = os.path.join(fx.dir, ".spike", "hooks")
    os.makedirs(hooks)
    for hook in ("pre-commit", "post-commit", "post-checkout", "reference-transaction"):
        with open(os.path.join(hooks, hook), "w") as handle:
            handle.write(f"#!/bin/sh\n: > '{os.path.join(fx.hit, 'core.hooksPath')}'\n")
        os.chmod(os.path.join(hooks, hook), 0o755)
    with open(os.path.join(fx.dir, "README"), "w") as handle:
        handle.write("fixture\n")
    host_git(fx.dir, "init", "-q", "-b", "main")
    host_git(fx.dir, "add", "README")
    host_git(fx.dir, "commit", "-q", "-m", "fixture")
    for setting in meta["settings"]:
        host_git(fx.dir, "config", setting["key"], fx.sub(setting["value"]).replace("@HOOKS@", hooks))
    repo_hook = os.path.join(fx.dir, ".git", "hooks", "pre-commit")
    with open(repo_hook, "w") as handle:
        handle.write(f"#!/bin/sh\n: > '{os.path.join(fx.hit, 'repo .git/hooks')}'\n")
    os.chmod(repo_hook, 0o755)

    wiring = [("http.proxy", s.proxy_url), ("http.sslCAInfo", s.ca)]
    base = s.base_env(fx.dir, [])
    base.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_TERMINAL_PROMPT": "0",
                 "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
                 "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid"})

    def env_with(pairs):
        env = dict(base)
        env["GIT_CONFIG_COUNT"] = str(len(pairs))
        for index, (key, value) in enumerate(pairs):
            env[f"GIT_CONFIG_KEY_{index}"] = key
            env[f"GIT_CONFIG_VALUE_{index}"] = value
        return env

    def run_all(label, env):
        fx.clear()
        shutil.rmtree(os.path.join(fx.dir, ".spike", "clone"), ignore_errors=True)
        per = {}
        for index, trigger in enumerate(meta["triggers"]):
            before = set(fx.hits())
            argv = [git] + [fx.sub(t) for t in trigger]
            r = s.run(f"{label}-{index}-{trigger[0]}", argv, env, fx.dir, fx.dir, timeout=60)
            per[" ".join(trigger[:2])] = {"rc": r["rc"], "new_hits": sorted(set(fx.hits()) - before)}
        return per, fx.hits()

    control, control_hits = run_all("forced-git-control", env_with(wiring))
    # The design's git row as merged in PR #196 (plus the file transport the
    # tools need), then the corrected row spike.git_env carries.
    design_pairs = wiring + [
        ("credential.helper", ""), ("core.fsmonitor", "false"), ("core.hooksPath", "/dev/null"),
        ("core.sshCommand", ""), ("protocol.allow", "never"), ("protocol.https.allow", "always"),
        ("protocol.file.allow", "always"), ("uploadpack.packObjectsHook", ""), ("core.askPass", ""),
    ]
    design, design_hits = run_all("forced-git-design", env_with(design_pairs))
    corrected_env = spike.git_env(s)
    corrected, corrected_hits = run_all("forced-git-corrected", env_with(pairs_of(corrected_env)))
    with open(os.path.join(s.work, "forced.jsonl"), "a") as handle:
        handle.write(json.dumps({"tool": "git", "control": control, "design": design,
                                 "corrected": corrected}) + "\n")
    s.claim("forced-git", "confirmed" if not design_hits else "refuted",
            f"control hits {control_hits}; design set hits {design_hits}; corrected set hits {corrected_hits}")


def pairs_of(env):
    count = int(env["GIT_CONFIG_COUNT"])
    return [(env[f"GIT_CONFIG_KEY_{i}"], env[f"GIT_CONFIG_VALUE_{i}"]) for i in range(count)]


def forced_go(s):
    go_root = s.obj("*-go-*")
    go = os.path.join(go_root, "bin", "go")
    meta = Fixture(s, "go", "forced-go-meta").meta

    def census_env(fx):
        spike_dir = os.path.join(fx.dir, ".spike")
        env = s.base_env(fx.dir, [os.path.join(go_root, "bin")])
        env.update({"GOTOOLCHAIN": "local", "GOROOT": go_root, "GOENV": "off", "GOWORK": "off",
                    "GOMODCACHE": spike_dir + "/modcache", "GOCACHE": spike_dir + "/gocache",
                    "GOFLAGS": "-mod=mod", "GOPROXY": s.mirror("go").rstrip("/"), "GOSUMDB": "sum.golang.org",
                    "GOVCS": "*:off", "GOAUTH": "off", "CGO_ENABLED": "0",
                    "HTTPS_PROXY": s.proxy_url, "HTTP_PROXY": s.proxy_url, "NO_PROXY": ""})
        env.update(spike.git_env(s))
        return env

    rows = {}
    for setting in meta["settings"]:
        label = f"forced-go-control-{setting['name']}"
        fx = Fixture(s, "go", label)
        env = census_env(fx)
        for key, value in setting["env"].items():
            env[key] = fx.sub(value)
        if "path_marker" in setting:
            fx.path_marker(setting["path_marker"], setting["name"])
            env["PATH"] = fx.path_bin + ":" + env["PATH"]
        if "gomod_append" in setting:
            with open(os.path.join(fx.dir, "go.mod"), "a") as handle:
                handle.write(setting["gomod_append"])
        r = s.run(label, [go, "mod", "tidy"], env, fx.dir, fx.dir, timeout=180)
        hits = fx.hits()
        if "detect_request" in setting:
            seen = [e.get("path", "") for e in s.requests(label) if setting["detect_request"] in e.get("path", "")]
            if seen:
                hits.append(f"{setting['name']} (requested {seen[0]})")
        rows[setting["name"]] = {"hits": hits, "rc": r["rc"]}
    fx = Fixture(s, "go", "forced-go-forced")
    with open(os.path.join(fx.dir, "go.mod"), "a") as handle:
        handle.write("".join(x.get("gomod_append", "") for x in meta["settings"]))
    for setting in meta["settings"]:
        if "path_marker" in setting:
            fx.path_marker(setting["path_marker"], setting["name"])
    r = s.run("forced-go-forced", [go, "mod", "tidy"], census_env(fx), fx.dir, fx.dir)
    hits = fx.hits() + [e["path"] for e in s.requests("forced-go-forced") if "golang.org/toolchain" in e.get("path", "")]
    record(s, "go", rows, hits, r["rc"], "(the forced environment is the census one, built from empty)")


def forced_by_design(s):
    # Bundler
    ruby = s.obj("*-ruby-*")
    fx = Fixture(s, "bundler", "forced-bundler")
    os.makedirs(os.path.join(fx.dir, ".bundle"))
    with open(os.path.join(fx.dir, ".bundle", "config"), "w") as handle:
        handle.write("---\n" + "".join(fx.sub(x["line"]) + "\n" for x in fx.meta["settings"]))
    gem_home = os.path.join(fx.dir, ".spike", "gems")
    env = s.base_env(fx.dir, [os.path.join(ruby, "bin")])
    env.update({"GEM_HOME": gem_home, "GEM_PATH": gem_home, "BUNDLE_FROZEN": "false",
                "BUNDLE_DISABLE_SHARED_GEMS": "true", "BUNDLE_AUTO_INSTALL": "false",
                "BUNDLE_DISABLE_VERSION_CHECK": "true", "GEMRC": "/dev/null",
                "https_proxy": s.proxy_url, "http_proxy": s.proxy_url,
                "BUNDLE_MIRROR__HTTPS://RUBYGEMS__ORG/": s.mirror("rubygems")})
    bundle = os.path.join(ruby, "bin", "bundle")
    r = s.run("forced-bundler-control", [bundle, "lock"], env, fx.dir, fx.dir)
    control = fx.hits()
    fx.clear()
    env.update({"BUNDLE_IGNORE_CONFIG": "1", "BUNDLE_GEMFILE": os.path.join(fx.dir, "Gemfile")})
    r2 = s.run("forced-bundler-forced", [bundle, "lock"], env, fx.dir, fx.dir)
    record(s, "bundler", {"control (no BUNDLE_IGNORE_CONFIG)": {"hits": control, "rc": r["rc"]}},
           [f"by-design:{h}" if h == "gemfile-eval" else h for h in fx.hits()], r2["rc"])
    # mix
    beam = s.obj("*-beam-*")
    fx = Fixture(s, "mix", "forced-mix")
    spike_dir = os.path.join(fx.dir, ".spike")
    env = s.base_env(fx.dir, [os.path.join(beam, "elixir", "bin"), os.path.join(beam, "otp", "bin")])
    env.update({"MIX_DEPS_PATH": spike_dir + "/deps", "MIX_ARCHIVES": os.path.join(beam, "archives"),
                "MIX_REBAR3": os.path.join(beam, "rebar3"), "MIX_HOME": spike_dir + "/mix",
                "HEX_HOME": spike_dir + "/hex", "MIX_TARGET": "host", "HEX_MIRROR": s.mirror("hex").rstrip("/"),
                "http_proxy": s.proxy_url, "https_proxy": s.proxy_url, "HEX_CACERTS_PATH": s.ca})
    r = s.run("forced-mix", [os.path.join(beam, "elixir", "bin", "mix"), "deps.get"], env, fx.dir, fx.dir)
    record(s, "mix", {}, [f"by-design:{h}" for h in fx.hits()], r["rc"])
    # dotnet
    sdk = s.obj("*-dotnet-sdk-*")
    fx = Fixture(s, "dotnet", "forced-dotnet")
    spike_dir = os.path.join(fx.dir, ".spike")
    config = os.path.join(spike_dir, "nuget.config")
    with open(config, "w") as handle:
        handle.write('<?xml version="1.0" encoding="utf-8"?>\n<configuration><packageSources><clear />'
                     f'<add key="tog" value="{s.mirror("nuget")}v3/index.json" protocolVersion="3" '
                     'allowInsecureConnections="true" /></packageSources></configuration>\n')
    env = s.base_env(fx.dir, [sdk])
    env.update({"DOTNET_ROOT": sdk, "NUGET_PACKAGES": spike_dir + "/pkgs", "DOTNET_CLI_TELEMETRY_OPTOUT": "1",
                "DOTNET_NOLOGO": "1", "DOTNET_CLI_HOME": spike_dir, "DOTNET_SKIP_FIRST_TIME_EXPERIENCE": "1",
                "HTTPS_PROXY": s.proxy_url, "HTTP_PROXY": s.proxy_url, "NUGET_CERT_REVOCATION_MODE": "offline",
                "DOTNET_EnableDiagnostics": "0", "MSBUILDDISABLENODEREUSE": "1",
                "DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE": "1"})
    r = s.run("forced-dotnet", [os.path.join(sdk, "dotnet"), "restore", "--use-lock-file", "--configfile", config,
                                "--disable-build-servers", "-maxcpucount:1"], env, fx.dir, fx.dir)
    record(s, "dotnet", {}, [f"by-design:{h}" for h in fx.hits()], r["rc"])


FORCED = {
    "npm": forced_npm,
    "pnpm": forced_pnpm,
    "cargo": forced_cargo,
    "uv": forced_uv,
    "git": forced_git,
    "go": forced_go,
    "by-design": forced_by_design,
}

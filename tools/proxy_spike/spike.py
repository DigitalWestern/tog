#!/usr/bin/env python3
"""Resolution-proxy evidence spike (PR 0 of docs/agent/DESIGNS.md §6).

Runs every census invocation through a logging proxy, inside the confinement
shape the door will use on Linux, and checks the design's † claims.

    python3 -m venv $W/venv && $W/venv/bin/pip install mitmproxy
    cc -O2 -o $W/nounix tools/proxy_spike/nounix.c
    tools/proxy_spike/spike.py --store $TOG_STORE --work $W --mitmdump $W/venv/bin/mitmdump \\
        --nounix $W/nounix census [ecosystem ...]
    tools/proxy_spike/spike.py --work $W report

`--store` is a tog store that already holds the toolchains (sync one fixture
project per ecosystem with the tog under test first; `tog add` in a Python
and a pnpm project realizes uv and pnpm). Every tool runs:

- under bwrap with `--unshare-net --unshare-pid --clearenv`, the host root
  read-only, fresh /tmp and /run, and only the scenario directory writable;
- behind `relay.py`, which is the only way out of the network namespace (a
  Unix socket bound at /run/tog/proxy.sock, spliced to 127.0.0.1:8119);
- under `nounix` (the AF_UNIX / io_uring / ptrace seccomp filter), traced by
  strace for `socket` and `io_uring_setup` so denied attempts are counted;
- with an environment built from empty.

The proxy is one mitmdump listener with `addon.py`: CONNECT-MITM with token
authentication for the interception ecosystems, `/<token>/<route>/` mirror
routes for the others. Outputs, all under --work:

    proxy.jsonl     every request, refusal, and error, labelled by scenario
    results.jsonl   every tool run: argv, exit status, AF_UNIX/io_uring counts
    claims.jsonl    every checked claim: id, verdict, evidence
    record/         upstream response bodies (with --record)
"""

import argparse
import base64
import glob
import hashlib
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.normpath(os.path.join(HERE, "..", ".."))
RELAY_PORT = 8119


# ---------------------------------------------------------------------------
# Session: proxy, host-side socket bridge, sandboxed runs


class Session:
    def __init__(self, args):
        self.args = args
        self.work = os.path.abspath(args.work)
        self.store = os.path.abspath(args.store) if args.store else None
        self.token = secrets.token_hex(16)
        self.log = os.path.join(self.work, "proxy.jsonl")
        self.results = os.path.join(self.work, "results.jsonl")
        self.claims = os.path.join(self.work, "claims.jsonl")
        self.label_file = os.path.join(self.work, "label")
        self.sockdir = os.path.join(self.work, "sock")
        self.confdir = os.path.join(self.work, "mitm")
        self.ca = os.path.join(self.confdir, "mitmproxy-ca-cert.pem")
        self.proc = None
        self.port = None

    # -- proxy lifecycle -----------------------------------------------------

    def start(self):
        os.makedirs(self.work, exist_ok=True)
        os.makedirs(self.sockdir, exist_ok=True)
        os.makedirs(self.confdir, exist_ok=True)
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            self.port = probe.getsockname()[1]
        command = [
            self.args.mitmdump,
            "--listen-host", "127.0.0.1",
            "--listen-port", str(self.port),
            "--set", f"confdir={self.confdir}",
            # The tog proxy offers only http/1.1 (design, "ALPN").
            "--set", "http2=false",
            "--set", "connection_strategy=lazy",
            "--set", "flow_detail=0",
            "-s", os.path.join(HERE, "addon.py"),
            "--set", f"spike_token={self.token}",
            "--set", f"spike_log={self.log}",
            "--set", f"spike_label_file={self.label_file}",
            "--set", f"spike_mirror_base=http://127.0.0.1:{self.tool_port}",
        ]
        if self.args.record:
            command += ["--set", f"spike_record_dir={os.path.join(self.work, 'record')}"]
        self.proc = subprocess.Popen(
            command, stdout=open(os.path.join(self.work, "mitmdump.out"), "a"), stderr=subprocess.STDOUT
        )
        for _ in range(100):
            if os.path.exists(self.ca):
                try:
                    socket.create_connection(("127.0.0.1", self.port), timeout=0.2).close()
                    break
                except OSError:
                    pass
            time.sleep(0.1)
        else:
            raise SystemExit("mitmdump did not start; see mitmdump.out")
        if self.args.engine == "bwrap":
            self._bridge(os.path.join(self.sockdir, "proxy.sock"), self.port)

    def stop(self):
        if self.proc:
            self.proc.terminate()
            self.proc.wait()

    def _bridge(self, path, port):
        if os.path.exists(path):
            os.unlink(path)
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(path)
        listener.listen(128)

        def pump(source, sink):
            try:
                while True:
                    data = source.recv(65536)
                    if not data:
                        break
                    sink.sendall(data)
            except OSError:
                pass
            finally:
                try:
                    sink.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

        def serve():
            while True:
                client, _ = listener.accept()
                upstream = socket.create_connection(("127.0.0.1", port))
                threading.Thread(target=pump, args=(client, upstream), daemon=True).start()
                threading.Thread(target=pump, args=(upstream, client), daemon=True).start()

        threading.Thread(target=serve, daemon=True).start()

    # -- URLs the tools see ----------------------------------------------------

    @property
    def tool_port(self):
        """The port tools dial: the relay's inside bwrap, the proxy's own under Seatbelt."""
        return RELAY_PORT if self.args.engine == "bwrap" else self.port

    @property
    def proxy_url(self):
        return f"http://tog:{self.token}@127.0.0.1:{self.tool_port}"

    def mirror(self, route):
        return f"http://127.0.0.1:{self.tool_port}/{self.token}/{route}/"

    # -- running tools -------------------------------------------------------------

    def label(self, name):
        with open(self.label_file, "w") as handle:
            handle.write(name)

    def scenario_dir(self, name, files=None):
        path = os.path.join(self.work, "scenarios", name)
        if os.path.exists(path):
            shutil.rmtree(path)
        os.makedirs(path)
        for rel, content in (files or {}).items():
            target = os.path.join(path, rel)
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with open(target, "w") as handle:
                handle.write(content)
        for sub in ("home", "tmp", "cache"):
            os.makedirs(os.path.join(path, ".spike", sub), exist_ok=True)
        return path

    def base_env(self, scenario, path_dirs):
        spike = os.path.join(scenario, ".spike")
        return {
            "PATH": ":".join(list(path_dirs) + ["/usr/bin", "/bin"]),
            "HOME": os.path.join(spike, "home"),
            "TMPDIR": os.path.join(spike, "tmp"),
            "LANG": "C.UTF-8",
            "USER": os.environ.get("USER", "tog"),
        }

    def run(self, name, argv, env, cwd, scenario, confined=True, seccomp=True, trace=True,
            allow_unix=False, timeout=900, stdin_null=True):
        """Run one tool invocation; record and return its result dict."""
        self.label(name)
        if confined and self.args.engine == "seatbelt":
            return self._run_seatbelt(name, argv, env, cwd, scenario, timeout)
        spike = os.path.join(scenario, ".spike")
        trace_file = os.path.join(spike, f"strace-{name}.txt")
        inner = list(argv)
        if seccomp:
            inner = [self.args.nounix] + (["--allow-unix"] if allow_unix else []) + ["--"] + inner
        if trace:
            inner = ["strace", "-f", "-qq", "-e", "trace=socket,connect,io_uring_setup,execve",
                     "-e", "signal=none", "-o", trace_file] + inner
        if confined:
            command = [
                "bwrap",
                "--ro-bind", "/", "/",
                "--dev", "/dev",
                "--proc", "/proc",
                "--tmpfs", "/tmp",
                "--tmpfs", "/run",
                "--ro-bind", self.sockdir, "/run/tog",
                "--bind", scenario, scenario,
                "--unshare-net", "--unshare-pid", "--unshare-ipc", "--unshare-uts",
                "--die-with-parent", "--new-session",
                "--clearenv",
            ]
            for key, value in env.items():
                command += ["--setenv", key, value]
            command += ["--chdir", cwd, "--", "/usr/bin/python3", os.path.join(HERE, "relay.py"),
                        "/run/tog/proxy.sock", str(RELAY_PORT), "--"] + inner
            run_env = {}
        else:
            command = inner
            run_env = dict(env)
        started = time.time()
        rc, out, err = execute(command, cwd, run_env, timeout, stdin_null)
        result = {
            "label": name,
            "argv": argv,
            "confined": confined,
            "seccomp": seccomp,
            "rc": rc,
            "seconds": round(time.time() - started, 1),
            "stdout": out.decode(errors="replace")[-3000:],
            "stderr": err.decode(errors="replace")[-3000:],
        }
        if trace and os.path.exists(trace_file):
            result.update(strace_counts(trace_file))
        with open(self.results, "a") as handle:
            handle.write(json.dumps(result) + "\n")
        mark = "ok " if rc == 0 else "ERR"
        print(f"[{mark}] {name}: rc={rc} {result.get('af_unix_denied', '-')} AF_UNIX denied, "
              f"{result.get('io_uring', '-')} io_uring, {result['seconds']}s", flush=True)
        if rc != 0 and self.args.verbose:
            print(result["stderr"][-1500:], flush=True)
        return result

    def _run_seatbelt(self, name, argv, env, cwd, scenario, timeout):
        """macOS: measure the Mach services one invocation needs.

        Runs under `(deny mach-lookup)` plus an allow-list, reads the denials
        from the unified log, allows every denied name and reruns, until the
        tool passes or no new name appears (at most 8 rounds). Records the
        final allow-list and every denial to WORK/mach.jsonl.
        """
        import mach_report

        allowed, rounds = [], []
        for _ in range(8):
            profile = mach_report.profile(allowed, self.tool_port)
            started_at = mach_report.log_timestamp()
            began = time.time()
            rc, out, err = execute(["/usr/bin/sandbox-exec", "-p", profile] + list(argv), cwd, dict(env),
                                   timeout, True)
            time.sleep(1.5)
            denied = mach_report.denials_since(started_at)
            rounds.append({"rc": rc, "allowed": list(allowed), "denied": denied,
                           "seconds": round(time.time() - began, 1)})
            new = sorted({d["service"] for d in denied} - set(allowed))
            if rc == 0 or not new:
                break
            allowed += new
        entry = {"label": name, "argv": argv, "rc": rc, "allowed": sorted(allowed),
                 "tolerated_denials": sorted({d["service"] for d in rounds[-1]["denied"]} - set(allowed)),
                 "rounds": rounds, "stderr": err.decode(errors="replace")[-2000:]}
        with open(os.path.join(self.work, "mach.jsonl"), "a") as handle:
            handle.write(json.dumps(entry) + "\n")
        result = {"label": name, "argv": argv, "confined": True, "seccomp": False, "rc": rc,
                  "seconds": rounds[-1]["seconds"], "stdout": out.decode(errors="replace")[-3000:],
                  "stderr": err.decode(errors="replace")[-3000:], "mach_allowed": sorted(allowed)}
        with open(self.results, "a") as handle:
            handle.write(json.dumps(result) + "\n")
        print(f"[{'ok ' if rc == 0 else 'ERR'}] {name}: rc={rc} mach allow-list {sorted(allowed)}", flush=True)
        return result

    def claim(self, claim_id, verdict, evidence):
        entry = {"claim": claim_id, "verdict": verdict, "evidence": evidence}
        with open(self.claims, "a") as handle:
            handle.write(json.dumps(entry) + "\n")
        print(f"  claim {claim_id}: {verdict} ({evidence[:160]})", flush=True)

    def requests(self, label):
        """Proxy log entries for one label."""
        entries = []
        if os.path.exists(self.log):
            with open(self.log) as handle:
                for line in handle:
                    entry = json.loads(line)
                    if entry.get("label") == label:
                        entries.append(entry)
        return entries

    # -- store objects ---------------------------------------------------------

    def obj(self, pattern):
        matches = sorted(glob.glob(os.path.join(self.store, "objects", pattern)))
        if not matches:
            raise SystemExit(f"no store object matches {pattern}; provision it first")
        return matches[-1]


def execute(command, cwd, env, timeout, stdin_null):
    try:
        completed = subprocess.run(
            command, cwd=cwd, env=env, capture_output=True, timeout=timeout,
            stdin=subprocess.DEVNULL if stdin_null else None,
        )
        return completed.returncode, completed.stdout, completed.stderr
    except subprocess.TimeoutExpired as expired:
        return "timeout", expired.stdout or b"", expired.stderr or b""


def strace_counts(path):
    af_unix_denied = io_uring = af_unix_attempts = 0
    denied_targets = set()
    programs = {}
    unix_programs, uring_programs = set(), set()
    with open(path, errors="replace") as handle:
        for line in handle:
            pid = line.split(" ", 1)[0]
            match = re.search(r'execve\("([^"]+)"', line)
            if match and "= 0" in line:
                programs[pid] = os.path.basename(match.group(1))
            if "socket(AF_UNIX" in line or "socket(AF_LOCAL" in line:
                af_unix_attempts += 1
                unix_programs.add(programs.get(pid, "?"))
                if "EAFNOSUPPORT" in line:
                    af_unix_denied += 1
            if "io_uring_setup(" in line:
                io_uring += 1
                uring_programs.add(programs.get(pid, "?"))
            match = re.search(r'connect\(\d+, \{sa_family=AF_UNIX, sun_path="([^"]+)"', line)
            if match:
                denied_targets.add(match.group(1))
    return {
        "af_unix_attempts": af_unix_attempts,
        "af_unix_denied": af_unix_denied,
        "io_uring": io_uring,
        "af_unix_connect_paths": sorted(denied_targets),
        "af_unix_programs": sorted(unix_programs),
        "io_uring_programs": sorted(uring_programs),
    }


def sha256(path):
    with open(path, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


def git_env(session, extra=()):
    """The git row: env-carried config (tools, not tog, run git)."""
    pairs = [
        ("http.proxy", session.proxy_url),
        ("http.sslCAInfo", session.ca),
        ("credential.helper", ""),
        ("core.fsmonitor", "false"),
        ("core.hooksPath", "/dev/null"),
        ("core.sshCommand", "false"),
        ("protocol.allow", "never"),
        ("protocol.https.allow", "always"),
        # uv and cargo clone their own local database into a checkout with
        # `git clone <path>`, which is the `file` transport.
        ("protocol.file.allow", "always"),
        # A per-protocol key in the repository's own config beats the
        # environment's protocol.allow (forced.py measures ext:: running), so
        # every other transport is named explicitly.
        ("protocol.ext.allow", "never"),
        ("protocol.ssh.allow", "never"),
        ("protocol.git.allow", "never"),
        ("protocol.http.allow", "never"),
        ("core.gitProxy", ""),
        ("uploadpack.packObjectsHook", ""),
        ("core.askPass", "false"),
        ("url.https://github.com/.insteadOf", "ssh://git@github.com/"),
        ("url.https://github.com/.insteadOf", "git@github.com:"),
    ] + list(extra)
    env = {
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_CONFIG_COUNT": str(len(pairs)),
    }
    for index, (key, value) in enumerate(pairs):
        env[f"GIT_CONFIG_KEY_{index}"] = key
        env[f"GIT_CONFIG_VALUE_{index}"] = value
    return env


# ---------------------------------------------------------------------------
# Census scenarios, one function per ecosystem


def census_python(s):
    uv = os.path.join(s.obj("*-uv-*"), "uv")
    python = os.path.join(s.obj("*-cpython-*"), "bin", "python3")
    version = re.search(r"cpython-(\d+\.\d+)", s.obj("*-cpython-*")).group(1)

    def env_for(scenario, **extra):
        env = s.base_env(scenario, [os.path.dirname(uv)])
        env.update({
            "UV_PYTHON": python,
            "UV_PYTHON_DOWNLOADS": "never",
            "UV_CACHE_DIR": os.path.join(scenario, ".spike", "cache", "uv"),
            "HTTPS_PROXY": s.proxy_url,
            "HTTP_PROXY": s.proxy_url,
            "NO_PROXY": "",
            "SSL_CERT_FILE": s.ca,
        })
        env.update(git_env(s))
        env.update(extra)
        return env

    # Missing lock / tog x: uv pip compile --generate-hashes.
    d = s.scenario_dir("py-missing-lock", {"requirements.in": "iniconfig\nsix==1.16.0\n"})
    s.run("py-missing-lock", [uv, "pip", "compile", "requirements.in", "--generate-hashes", "--quiet",
                              "--python", python, "--python-version", version, "--index-url", "https://pypi.org/simple",
                              "-o", "requirements.lock.txt"], env_for(d), d, d)

    # Build requirements: --no-build (pypi.rs).
    d = s.scenario_dir("py-build-reqs", {"requirements.in": "setuptools>=61\nwheel\n"})
    s.run("py-build-reqs", [uv, "pip", "compile", "--generate-hashes", "--python", python, "--python-version", version,
                            "--no-build", "requirements.in", "-o", "requirements.lock.txt"],
          env_for(d), d, d)

    # --no-build error form: an sdist-only dependency.
    d = s.scenario_dir("py-no-build-sdist", {"requirements.in": "docopt==0.6.2\n"})
    r = s.run("py-no-build-sdist", [uv, "pip", "compile", "--generate-hashes", "--python", python,
                                    "--python-version", version, "--no-build", "--index-url", "https://pypi.org/simple",
                                    "requirements.in", "-o", "requirements.lock.txt"],
              env_for(d), d, d)
    s.claim("uv-no-build-error-form", "confirmed" if r["rc"] != 0 else "refuted",
            f"rc={r['rc']} stderr={r['stderr'].strip()!r}")

    # Edit verbs: uv add / remove / lock on a project.
    pyproject = (
        "[project]\nname = \"spike\"\nversion = \"0.1.0\"\nrequires-python = \">=3.12\"\n"
        "dependencies = []\n"
    )
    d = s.scenario_dir("py-edit", {"pyproject.toml": pyproject})
    s.run("py-edit-add", [uv, "add", "--no-sync", "--default-index", "https://pypi.org/simple",
                          "--", "iniconfig"], env_for(d), d, d)
    s.run("py-edit-add-git", [uv, "add", "--no-sync", "--default-index", "https://pypi.org/simple",
                              "--", "git+https://github.com/pytest-dev/iniconfig@v2.0.0"],
          env_for(d), d, d)
    s.run("py-edit-remove", [uv, "remove", "--no-sync", "--", "iniconfig"], env_for(d), d, d)
    s.run("py-edit-lock", [uv, "lock", "--upgrade", "--default-index", "https://pypi.org/simple"],
          env_for(d), d, d)

    # Attest: uv lock --locked leaves the lock byte-unchanged; a drift fails.
    before = sha256(os.path.join(d, "uv.lock"))
    r = s.run("py-attest", [uv, "lock", "--locked", "--default-index", "https://pypi.org/simple"],
              env_for(d), d, d)
    unchanged = before == sha256(os.path.join(d, "uv.lock"))
    with open(os.path.join(d, "pyproject.toml"), "a") as handle:
        handle.write("\n[project.optional-dependencies]\nx = [\"six\"]\n")
    r2 = s.run("py-attest-drift", [uv, "lock", "--locked", "--default-index",
                                   "https://pypi.org/simple"], env_for(d), d, d)
    s.claim("attest-uv-lock-locked",
            "confirmed" if r["rc"] == 0 and unchanged and r2["rc"] != 0 else "refuted",
            f"unchanged lock rc={r['rc']} bytes-unchanged={unchanged}; drift rc={r2['rc']} "
            f"stderr={r2['stderr'].strip()[-200:]!r}")

    # --no-build-package <member>: a member with dynamic metadata.
    member = (
        "[build-system]\nrequires = [\"setuptools>=61\"]\nbuild-backend = \"setuptools.build_meta\"\n\n"
        "[project]\nname = \"dyn\"\ndynamic = [\"version\"]\nrequires-python = \">=3.12\"\n"
        "dependencies = [\"iniconfig\"]\n\n[tool.setuptools.dynamic]\nversion = {attr = \"dyn.VERSION\"}\n"
    )
    d = s.scenario_dir("py-dynamic-member", {"pyproject.toml": member, "dyn/__init__.py": "VERSION = '1.2.3'\n"})
    probe = s.run("py-probe-no-build", [uv, "lock", "--no-build", "--default-index",
                                        "https://pypi.org/simple"], env_for(d), d, d)
    exempt = s.run("py-probe-no-build-package", [uv, "lock", "--no-build", "--no-build-package", "dyn",
                                                 "--default-index", "https://pypi.org/simple"],
                   env_for(d), d, d)
    plain = s.run("py-probe-builds", [uv, "lock", "--default-index", "https://pypi.org/simple"],
                  env_for(d), d, d)
    s.claim("uv-no-build-package-exempts-member",
            "confirmed" if exempt["rc"] == 0 and probe["rc"] != 0 else "refuted",
            f"--no-build rc={probe['rc']} ({probe['stderr'].strip()[-240:]!r}); "
            f"--no-build --no-build-package dyn rc={exempt['rc']} ({exempt['stderr'].strip()[-240:]!r}); "
            f"no flags rc={plain['rc']}")
    # The replacement: build only the member's metadata first (its build
    # requirements wheel-only), then the --no-build probe reuses the cache.
    os.remove(os.path.join(d, "uv.lock"))
    member_in = os.path.join(d, ".spike", "member.in")
    with open(member_in, "w") as handle:
        handle.write(f"-e {d}\n")
    pre = s.run("py-probe-member-metadata", [uv, "pip", "compile", "--no-deps", "--python", python,
                                             "--only-binary", "setuptools", "--index-url",
                                             "https://pypi.org/simple", member_in, "-o",
                                             os.path.join(d, ".spike", "member.out")], env_for(d), d, d)
    after = s.run("py-probe-after-member", [uv, "lock", "--no-build", "--default-index",
                                            "https://pypi.org/simple"], env_for(d), d, d)
    s.claim("uv-member-metadata-then-no-build", "confirmed" if pre["rc"] == 0 and after["rc"] == 0 else "refuted",
            f"member metadata step rc={pre['rc']}; then uv lock --no-build rc={after['rc']}")

    # SSL_CERT_FILE is uv's whole root set: without the proxy, pypi.org fails.
    d = s.scenario_dir("py-cafile-replaces", {"requirements.in": "iniconfig\n"})
    env = env_for(d)
    for key in ("HTTPS_PROXY", "HTTP_PROXY"):
        env.pop(key)
    env["UV_NATIVE_TLS"] = "false"
    direct = s.run("py-cafile-direct", [uv, "pip", "compile", "requirements.in", "--index-url",
                                        "https://pypi.org/simple", "-o", "out.txt"],
                   env, d, d, confined=False, seccomp=False, trace=False)
    env.pop("SSL_CERT_FILE")
    control = s.run("py-cafile-direct-control", [uv, "pip", "compile", "requirements.in", "--index-url",
                                                 "https://pypi.org/simple", "-o", "out.txt"],
                    env, d, d, confined=False, seccomp=False, trace=False)
    s.claim("uv-ssl-cert-file-replaces-roots",
            "confirmed" if direct["rc"] != 0 and control["rc"] == 0 else "refuted",
            f"direct with SSL_CERT_FILE=tog CA rc={direct['rc']} "
            f"({direct['stderr'].strip()[-200:]!r}); without it rc={control['rc']}")
    # And through the proxy it works (the census runs above), which needs the file.
    d = s.scenario_dir("py-no-cafile", {"requirements.in": "iniconfig\n"})
    env = env_for(d)
    env.pop("SSL_CERT_FILE")
    r = s.run("py-no-cafile", [uv, "pip", "compile", "requirements.in", "--index-url",
                               "https://pypi.org/simple", "-o", "out.txt"], env, d, d)
    s.claim("uv-needs-ssl-cert-file-through-proxy", "confirmed" if r["rc"] != 0 else "refuted",
            f"through the proxy without SSL_CERT_FILE rc={r['rc']}")


def node_paths(s):
    node = s.obj("*-nodejs-*")
    pnpm_bins = sorted(glob.glob(os.path.join(s.store, "objects", "*", "node_modules", ".bin", "pnpm")))
    return node, (pnpm_bins[-1] if pnpm_bins else None)


def census_npm(s):
    node, _ = node_paths(s)
    npm = os.path.join(node, "bin", "npm")

    def flags(notifier=False):
        return [f"--proxy={s.proxy_url}", f"--https-proxy={s.proxy_url}", "--noproxy=",
                "--registry=https://registry.npmjs.org/", "--strict-ssl=true", f"--cafile={s.ca}"] + (
                    [] if notifier else ["--update-notifier=false"])

    def env_for(scenario):
        env = s.base_env(scenario, [os.path.join(node, "bin")])
        env["NODE_EXTRA_CA_CERTS"] = s.ca
        env["npm_config_cache"] = os.path.join(scenario, ".spike", "cache", "npm")
        env.update(git_env(s))
        return env

    package = json.dumps({"name": "spike", "version": "1.0.0", "dependencies": {"is-number": "^7.0.0"}},
                         indent=2) + "\n"
    # Today's flags leave npm's update notifier on: it fetches the whole npm packument.
    d = s.scenario_dir("npm-update-notifier", {"package.json": package})
    s.run("npm-update-notifier", [npm, "--silent", "install", "--package-lock-only", "--ignore-scripts"]
          + flags(notifier=True), env_for(d), d, d)
    notifier = [e for e in s.requests("npm-update-notifier") if e.get("path") == "/npm"]
    s.claim("npm-update-notifier", "observed",
            f"without --update-notifier=false npm fetched /npm {len(notifier)}x "
            f"({notifier[0]['bytes'] if notifier else 0} bytes)")
    d = s.scenario_dir("npm-missing-lock", {"package.json": package})
    s.run("npm-missing-lock", [npm, "--silent", "install", "--package-lock-only", "--ignore-scripts"] + flags(),
          env_for(d), d, d)
    s.run("npm-add", [npm, "--silent", "install", "--package-lock-only", "--ignore-scripts"] + flags()
          + ["--", "is-odd@3.0.1"], env_for(d), d, d)
    s.run("npm-update", [npm, "--silent", "update", "--package-lock-only", "--ignore-scripts"] + flags(),
          env_for(d), d, d)
    s.run("npm-remove", [npm, "--silent", "uninstall", "--package-lock-only", "--ignore-scripts"] + flags()
          + ["--", "is-odd"], env_for(d), d, d)
    before = sha256(os.path.join(d, "package-lock.json"))
    r = s.run("npm-attest", [npm, "--silent", "install", "--package-lock-only", "--ignore-scripts"] + flags(),
              env_for(d), d, d)
    unchanged = before == sha256(os.path.join(d, "package-lock.json"))
    manifest = json.load(open(os.path.join(d, "package.json")))
    manifest["dependencies"]["is-number"] = "^6.0.0"
    json.dump(manifest, open(os.path.join(d, "package.json"), "w"), indent=2)
    r2 = s.run("npm-attest-drift", [npm, "--silent", "install", "--package-lock-only", "--ignore-scripts"]
               + flags(), env_for(d), d, d)
    changed = before != sha256(os.path.join(d, "package-lock.json"))
    s.claim("attest-npm-lock-unchanged",
            "confirmed" if r["rc"] == 0 and unchanged and changed else "refuted",
            f"consistent lock rc={r['rc']} bytes-unchanged={unchanged}; drifted manifest rc={r2['rc']} "
            f"lock rewritten={changed} (the check is the byte diff, npm exits 0 either way)")

    # Git and URL dependencies (git CLI through the git row).
    package = json.dumps({"name": "spike-git", "version": "1.0.0", "dependencies": {
        "is-number": "github:jonschlinkert/is-number#7.0.0",
        "is-odd": "https://registry.npmjs.org/is-odd/-/is-odd-3.0.1.tgz",
    }}, indent=2) + "\n"
    d = s.scenario_dir("npm-git-url-deps", {"package.json": package})
    s.run("npm-git-url-deps", [npm, "--silent", "install", "--package-lock-only", "--ignore-scripts"] + flags(),
          env_for(d), d, d)

    # --cafile replaces the roots for npm's own requests: direct, no proxy.
    d = s.scenario_dir("npm-cafile-replaces", {"package.json": package.replace("spike-git", "x")})
    env = env_for(d)
    env.pop("NODE_EXTRA_CA_CERTS")
    direct_flags = ["--registry=https://registry.npmjs.org/", f"--cafile={s.ca}", "--fetch-retries=0"]
    direct = s.run("npm-cafile-direct", [npm, "view", "is-number", "version"] + direct_flags,
                   env, d, d, confined=False, seccomp=False, trace=False)
    control = s.run("npm-cafile-direct-control", [npm, "view", "is-number", "version",
                                                  "--registry=https://registry.npmjs.org/"],
                    env, d, d, confined=False, seccomp=False, trace=False)
    s.claim("npm-cafile-replaces-roots",
            "confirmed" if direct["rc"] != 0 and control["rc"] == 0 else "refuted",
            f"direct with --cafile=tog CA rc={direct['rc']} ({direct['stderr'].strip()[-160:]!r}); "
            f"without rc={control['rc']}")


def census_pnpm(s):
    node, pnpm = node_paths(s)
    if not pnpm:
        raise SystemExit("no pnpm in the store; run `tog add` in a pnpm project first")
    tool_root = os.path.dirname(os.path.dirname(os.path.dirname(pnpm)))

    def env_for(scenario, rc_lines=None):
        env = s.base_env(scenario, [os.path.join(node, "bin"), os.path.dirname(pnpm)])
        home = os.path.join(scenario, ".spike", "home")
        env.update({
            "XDG_CONFIG_HOME": os.path.join(home, "xdg-config"),
            "XDG_DATA_HOME": os.path.join(home, "xdg-data"),
            "XDG_CACHE_HOME": os.path.join(home, "xdg-cache"),
            "XDG_STATE_HOME": os.path.join(home, "xdg-state"),
            "CI": "1",
            "npm_config_ignore_scripts": "true",
            "NODE_EXTRA_CA_CERTS": s.ca,
        })
        env.update(git_env(s))
        rc_dir = os.path.join(home, "xdg-config", "pnpm")
        os.makedirs(rc_dir, exist_ok=True)
        lines = [f"cafile={s.ca}"] if rc_lines is None else rc_lines
        with open(os.path.join(rc_dir, "rc"), "w") as handle:
            handle.write("".join(line + "\n" for line in lines))
        return env

    def args(scenario, verb, extra=()):
        spike = os.path.join(scenario, ".spike")
        out = [pnpm, verb, "--lockfile-only"]
        if verb != "remove":
            out.append("--ignore-scripts")
        out += ["--reporter", "append-only", "--config.enable-modules-dir=false",
                "--config.node-linker=isolated",
                f"--config.modules-dir={spike}/modules", f"--config.virtual-store-dir={spike}/vstore",
                f"--config.store-dir={spike}/store"]
        return out + list(extra)

    version = os.path.basename(tool_root)
    package = json.dumps({"name": "spike", "version": "1.0.0", "packageManager": "pnpm@9.15.4",
                          "dependencies": {"is-number": "^7.0.0"}}, indent=2) + "\n"

    # Which proxy spellings does pnpm accept and honor? Each variant runs on a
    # fresh project; the network only reaches the proxy, so "honored" means
    # tunnels were seen and the install passed.
    variants = {
        "design-flags": ([f"--http-proxy={s.proxy_url}", f"--https-proxy={s.proxy_url}", "--no-proxy="], {}, []),
        "flags": ([f"--proxy={s.proxy_url}", f"--https-proxy={s.proxy_url}", "--noproxy="], {}, []),
        "https-proxy-flag-only": ([f"--https-proxy={s.proxy_url}"], {}, []),
        "config-flags": ([f"--config.proxy={s.proxy_url}", f"--config.https-proxy={s.proxy_url}",
                          "--config.noproxy="], {}, []),
        "env": ([], {"HTTPS_PROXY": s.proxy_url, "HTTP_PROXY": s.proxy_url, "NO_PROXY": ""}, []),
        "xdg-rc": ([], {}, [f"https-proxy={s.proxy_url}", f"proxy={s.proxy_url}", "noproxy="]),
    }
    honored = {}
    for name, (flag_list, extra_env, rc_extra) in variants.items():
        d = s.scenario_dir(f"pnpm-proxy-{name}", {"package.json": package})
        env = env_for(d, rc_lines=[f"cafile={s.ca}"] + rc_extra)
        env.update(extra_env)
        r = s.run(f"pnpm-proxy-{name}", args(d, "install", flag_list), env, d, d, timeout=120)
        tunnels = [e for e in s.requests(f"pnpm-proxy-{name}") if e["event"] == "connect"]
        honored[name] = (r["rc"], len(tunnels), (r["stdout"] + r["stderr"]).strip()[-160:])
    s.claim("pnpm-proxy-flags",
            "confirmed" if honored["design-flags"][0] == 0 and honored["design-flags"][1] else "refuted",
            "; ".join(f"{k}: rc={v[0]} tunnels={v[1]}" + (f" ({v[2]!r})" if v[0] else "")
                      for k, v in honored.items()))
    s.claim("pnpm-ignores-config-proxy",
            "confirmed" if not honored["config-flags"][1] else "refuted",
            f"--config.proxy/--config.https-proxy: rc={honored['config-flags'][0]} "
            f"tunnels={honored['config-flags'][1]}")
    # `pnpm remove` rejects --proxy/--https-proxy/--noproxy, so every verb
    # gets the --config.* spelling, which every verb's parser accepts.
    proxy_flags = [f"--config.proxy={s.proxy_url}", f"--config.https-proxy={s.proxy_url}",
                   "--config.noproxy="]
    d = s.scenario_dir("pnpm-edit", {"package.json": package})
    s.run("pnpm-missing-lock", args(d, "install") + proxy_flags, env_for(d), d, d)
    s.run("pnpm-add", args(d, "add", proxy_flags + ["is-odd@3.0.1"]), env_for(d), d, d)
    s.run("pnpm-update", args(d, "update", proxy_flags), env_for(d), d, d)
    s.run("pnpm-remove", args(d, "remove", proxy_flags + ["is-odd"]), env_for(d), d, d)
    before = sha256(os.path.join(d, "pnpm-lock.yaml"))
    r = s.run("pnpm-attest", args(d, "install", proxy_flags + ["--frozen-lockfile"]), env_for(d), d, d)
    unchanged = before == sha256(os.path.join(d, "pnpm-lock.yaml"))
    manifest = json.load(open(os.path.join(d, "package.json")))
    manifest["dependencies"]["is-number"] = "^6.0.0"
    json.dump(manifest, open(os.path.join(d, "package.json"), "w"), indent=2)
    r2 = s.run("pnpm-attest-drift", args(d, "install", proxy_flags + ["--frozen-lockfile"]),
               env_for(d), d, d)
    s.claim("attest-pnpm-frozen-lockfile",
            "confirmed" if r["rc"] == 0 and unchanged and r2["rc"] != 0 else "refuted",
            f"consistent rc={r['rc']} bytes-unchanged={unchanged}; drift rc={r2['rc']} "
            f"({r2['stdout'].strip()[-200:]!r})")

    # How pnpm takes the CA. Each variant supplies it one way only.
    ca_text = open(s.ca).read().strip().replace("\n", "\\n")
    ca_variants = {
        "none": ([], [], False),
        "xdg-rc-cafile": ([], [f"cafile={s.ca}"], False),
        "xdg-rc-ca": ([], [f"ca=\"{ca_text}\""], False),
        "config-cafile-flag": ([f"--config.cafile={s.ca}"], [], False),
        "node-extra-ca-certs": ([], [], True),
    }
    outcome = {}
    for name, (flag_list, rc_lines, extra_ca) in ca_variants.items():
        d = s.scenario_dir(f"pnpm-ca-{name}", {"package.json": package})
        env = env_for(d, rc_lines=rc_lines)
        if not extra_ca:
            env.pop("NODE_EXTRA_CA_CERTS")
        r = s.run(f"pnpm-ca-{name}", args(d, "install", proxy_flags + flag_list + ["--config.fetch-retries=0"]),
                  env, d, d, timeout=120)
        outcome[name] = r["rc"]
    s.claim("pnpm-cafile-in-xdg-rc", "confirmed" if outcome["xdg-rc-cafile"] == 0 else "refuted",
            "; ".join(f"{k}: rc={v}" for k, v in outcome.items()) + f" ({version})")
    # --config.cafile replaces the roots for pnpm's requests: direct, no proxy.
    d = s.scenario_dir("pnpm-cafile-replaces", {"package.json": package})
    env = env_for(d, rc_lines=[])
    env.pop("NODE_EXTRA_CA_CERTS")
    direct = s.run("pnpm-cafile-direct", args(d, "install", [f"--config.cafile={s.ca}",
                                                             "--config.fetch-retries=0"]),
                   env, d, d, confined=False, seccomp=False, trace=False, timeout=120)
    d = s.scenario_dir("pnpm-cafile-replaces-control", {"package.json": package})
    env = env_for(d, rc_lines=[])
    env.pop("NODE_EXTRA_CA_CERTS")
    control = s.run("pnpm-cafile-direct-control", args(d, "install", ["--config.fetch-retries=0"]),
                    env, d, d, confined=False, seccomp=False, trace=False, timeout=120)
    s.claim("pnpm-config-cafile-replaces-roots",
            "confirmed" if direct["rc"] != 0 and control["rc"] == 0 else "refuted",
            f"direct with --config.cafile=tog CA rc={direct['rc']}; without rc={control['rc']}")


def census_cargo(s):
    rust = s.obj("*-rust-*")
    cargo = os.path.join(rust, "bin", "cargo")

    def env_for(scenario):
        env = s.base_env(scenario, [os.path.join(rust, "bin")])
        env.update({"CARGO_HOME": os.path.join(scenario, ".spike", "cargo-home"), "CARGO_NET_OFFLINE": "false"})
        env.update(git_env(s))
        return env

    def cfg():
        return ["--config", f"http.proxy=\"{s.proxy_url}\"", "--config", f"http.cainfo=\"{s.ca}\"",
                "--config", "net.git-fetch-with-cli=true"]

    manifest = ("[package]\nname = \"spike\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n"
                "[dependencies]\nitoa = \"1\"\n")
    d = s.scenario_dir("cargo-edit", {"Cargo.toml": manifest, "src/lib.rs": ""})
    s.run("cargo-missing-lock", [cargo] + cfg() + ["generate-lockfile"], env_for(d), d, d)
    s.run("cargo-add", [cargo] + cfg() + ["add", "--", "ryu"], env_for(d), d, d)
    s.run("cargo-update", [cargo] + cfg() + ["update"], env_for(d), d, d)
    s.run("cargo-remove", [cargo] + cfg() + ["remove", "--", "ryu"], env_for(d), d, d)
    before = sha256(os.path.join(d, "Cargo.lock"))
    r = s.run("cargo-attest", [cargo] + cfg() + ["metadata", "--locked", "--format-version", "1"],
              env_for(d), d, d)
    unchanged = before == sha256(os.path.join(d, "Cargo.lock"))
    with open(os.path.join(d, "Cargo.toml"), "a") as handle:
        handle.write("ryu = \"1\"\n")
    r2 = s.run("cargo-attest-drift", [cargo] + cfg() + ["metadata", "--locked", "--format-version", "1"],
               env_for(d), d, d)
    s.claim("attest-cargo-metadata-locked",
            "confirmed" if r["rc"] == 0 and unchanged and r2["rc"] != 0 else "refuted",
            f"consistent rc={r['rc']} bytes-unchanged={unchanged}; drift rc={r2['rc']} "
            f"({r2['stderr'].strip()[-200:]!r})")

    manifest_git = manifest + "ryu = { git = \"https://github.com/dtolnay/ryu\", tag = \"1.0.18\" }\n"
    d = s.scenario_dir("cargo-git-dep", {"Cargo.toml": manifest_git, "src/lib.rs": ""})
    s.run("cargo-git-dep", [cargo] + cfg() + ["generate-lockfile"], env_for(d), d, d)

    d = s.scenario_dir("cargo-cainfo-replaces", {"Cargo.toml": manifest, "src/lib.rs": ""})
    direct = s.run("cargo-cainfo-direct", [cargo, "--config", f"http.cainfo=\"{s.ca}\"", "generate-lockfile"],
                   env_for(d), d, d, confined=False, seccomp=False, trace=False)
    shutil.rmtree(os.path.join(d, ".spike", "cargo-home"), ignore_errors=True)
    control = s.run("cargo-cainfo-direct-control", [cargo, "generate-lockfile"], env_for(d), d, d,
                    confined=False, seccomp=False, trace=False)
    s.claim("cargo-http-cainfo-replaces-roots",
            "confirmed" if direct["rc"] != 0 and control["rc"] == 0 else "refuted",
            f"direct with http.cainfo=tog CA rc={direct['rc']} ({direct['stderr'].strip()[-160:]!r}); "
            f"without rc={control['rc']}")


def census_go(s):
    go_root = s.obj("*-go-*")
    go = os.path.join(go_root, "bin", "go")

    def env_for(scenario):
        spike = os.path.join(scenario, ".spike")
        env = s.base_env(scenario, [os.path.join(go_root, "bin")])
        env.update({
            "GOTOOLCHAIN": "local", "GOROOT": go_root, "GOENV": "off", "GOWORK": "off",
            "GOMODCACHE": os.path.join(spike, "modcache"), "GOCACHE": os.path.join(spike, "gocache"),
            "GOFLAGS": "-mod=mod", "GOPROXY": s.mirror("go").rstrip("/"), "GOSUMDB": "sum.golang.org",
            "GOVCS": "*:off", "GOAUTH": "off", "CGO_ENABLED": "0",
            "HTTPS_PROXY": s.proxy_url, "HTTP_PROXY": s.proxy_url, "NO_PROXY": "",
        })
        return env

    files = {
        "go.mod": "module spike\n\ngo 1.23\n",
        "main.go": "package main\n\nimport \"github.com/google/uuid\"\n\nfunc main() { _ = uuid.New() }\n",
    }
    d = s.scenario_dir("go-edit", files)
    s.run("go-missing-lock-tidy", [go, "mod", "tidy"], env_for(d), d, d)
    s.run("go-missing-lock-download", [go, "mod", "download", "-json", "all"], env_for(d), d, d)
    s.run("go-planner-tidy-diff", [go, "mod", "tidy", "-diff"], env_for(d), d, d)
    s.run("go-get", [go, "get", "golang.org/x/sync@v0.10.0"], env_for(d), d, d)
    s.run("go-get-update", [go, "get", "-u", "./..."], env_for(d), d, d)
    s.run("go-get-remove", [go, "get", "golang.org/x/sync@none"], env_for(d), d, d)
    # `go get x@none` leaves x's go.sum lines; the sync after an edit tidies.
    s.run("go-tidy-after-edit", [go, "mod", "tidy"], env_for(d), d, d)
    before = (sha256(os.path.join(d, "go.mod")), sha256(os.path.join(d, "go.sum")))
    shutil.rmtree(os.path.join(d, ".spike", "modcache"), ignore_errors=True)
    r = s.run("go-attest-tidy-diff", [go, "mod", "tidy", "-diff"], env_for(d), d, d)
    r_dl = s.run("go-attest-download", [go, "mod", "download", "-json", "all"], env_for(d), d, d)
    unchanged = before == (sha256(os.path.join(d, "go.mod")), sha256(os.path.join(d, "go.sum")))
    with open(os.path.join(d, "go.sum")) as handle:
        lines = handle.readlines()
    with open(os.path.join(d, "go.sum"), "w") as handle:
        handle.writelines(lines[1:])
    r2 = s.run("go-attest-drift", [go, "mod", "tidy", "-diff"], env_for(d), d, d)
    s.claim("attest-go-tidy-diff-download",
            "confirmed" if r["rc"] == 0 and r_dl["rc"] == 0 and unchanged and r2["rc"] != 0 else "refuted",
            f"tidy -diff rc={r['rc']}, download rc={r_dl['rc']}, bytes-unchanged={unchanged}; "
            f"drift rc={r2['rc']}")
    sumdb = [e for e in s.requests("go-missing-lock-tidy") + s.requests("go-attest-download")
             if e.get("dialect") == "mirror:go" and e["host"] == "sum.golang.org"]
    supported = [e for e in s.requests("go-missing-lock-tidy") if e.get("path", "").endswith("/supported")]
    direct = [e for e in s.requests("go-missing-lock-tidy") if e["event"] == "connect"]
    s.claim("go-sumdb-through-proxy", "confirmed" if sumdb and not direct else "refuted",
            f"{len(sumdb)} sum.golang.org requests through the mirror route, "
            f"/supported asked {len(supported)}x, CONNECT tunnels {len(direct)}")


RUBY_GEMFILE = 'source "https://rubygems.org"\n\ngem "rake"\n'


def census_ruby(s):
    ruby = s.obj("*-ruby-*")
    mirror_key = "BUNDLE_MIRROR__HTTPS://RUBYGEMS__ORG/"

    def env_for(scenario, frozen="false", mirror_env=True, app_config=None):
        spike = os.path.join(scenario, ".spike")
        gem_home = os.path.join(spike, "gems")
        env = s.base_env(scenario, [os.path.join(ruby, "bin")])
        env.update({
            "GEM_HOME": gem_home, "GEM_PATH": gem_home, "BUNDLE_IGNORE_CONFIG": "1",
            "BUNDLE_GEMFILE": os.path.join(scenario, "Gemfile"), "BUNDLE_FROZEN": frozen,
            "BUNDLE_DISABLE_SHARED_GEMS": "true", "BUNDLE_AUTO_INSTALL": "false",
            "BUNDLE_DISABLE_VERSION_CHECK": "true", "GEMRC": "/dev/null",
            "https_proxy": s.proxy_url, "http_proxy": s.proxy_url,
        })
        if mirror_env:
            env[mirror_key] = s.mirror("rubygems")
        if app_config:
            env["BUNDLE_APP_CONFIG"] = app_config
        env.update(git_env(s))
        return env

    bundle = os.path.join(ruby, "bin", "bundle")
    d = s.scenario_dir("ruby-edit", {"Gemfile": RUBY_GEMFILE})
    s.run("ruby-missing-lock", [bundle, "lock"], env_for(d), d, d)
    helper = extract_ruby_helper()
    helper_path = os.path.join(d, ".spike", "helper.rb")
    with open(helper_path, "w") as handle:
        handle.write(helper)
    r = s.run("ruby-gate1-helper-check", [os.path.join(ruby, "bin", "ruby"), helper_path, "check",
                                          os.path.join(d, "Gemfile"), os.path.join(d, "Gemfile.lock")],
              env_for(d, frozen="true", mirror_env=False) | {"https_proxy": "", "http_proxy": ""}, d, d)
    seen = s.requests("ruby-gate1-helper-check")
    s.claim("ruby-gate1-needs-no-network", "confirmed" if r["rc"] == 0 and not seen else "refuted",
            f"helper check with no proxy settings rc={r['rc']}, proxy requests={len(seen)}")
    s.run("ruby-add", [bundle, "add", "rainbow"], env_for(d), d, d)
    s.run("ruby-update", [bundle, "update"], env_for(d), d, d)
    s.run("ruby-remove", [bundle, "remove", "rainbow"], env_for(d), d, d)
    before = sha256(os.path.join(d, "Gemfile.lock"))
    r = s.run("ruby-attest", [bundle, "lock"], env_for(d), d, d)
    unchanged = before == sha256(os.path.join(d, "Gemfile.lock"))
    with open(os.path.join(d, "Gemfile"), "a") as handle:
        handle.write('gem "rainbow"\n')
    r2 = s.run("ruby-attest-drift", [bundle, "lock"], env_for(d), d, d)
    changed = before != sha256(os.path.join(d, "Gemfile.lock"))
    s.claim("attest-bundle-lock-unchanged", "confirmed" if r["rc"] == 0 and unchanged and changed else "refuted",
            f"consistent rc={r['rc']} bytes-unchanged={unchanged}; drift rc={r2['rc']} lock rewritten={changed}")
    with open(os.path.join(d, "Gemfile.lock")) as handle:
        remote_kept = "remote: https://rubygems.org/" in handle.read()

    # The mirror as a config file in BUNDLE_APP_CONFIG (the design's wording),
    # under tog's BUNDLE_IGNORE_CONFIG=1, versus the environment variable.
    d2 = s.scenario_dir("ruby-mirror-config-file", {"Gemfile": RUBY_GEMFILE})
    app_config = os.path.join(d2, ".spike", "bundle-config")
    os.makedirs(app_config)
    with open(os.path.join(app_config, "config"), "w") as handle:
        handle.write(f'---\n{mirror_key}: "{s.mirror("rubygems")}"\n')
    r_file = s.run("ruby-mirror-config-file", [bundle, "lock"],
                   env_for(d2, mirror_env=False, app_config=app_config), d2, d2, timeout=300)
    via_file = [e for e in s.requests("ruby-mirror-config-file") if e.get("dialect") == "mirror:rubygems"]
    via_env = [e for e in s.requests("ruby-missing-lock") if e.get("dialect") == "mirror:rubygems"]
    tunnels = [e for e in s.requests("ruby-missing-lock") if e["event"] == "connect"]
    s.claim("bundler-mirror-setting",
            "confirmed-with-correction" if via_env and not via_file else ("confirmed" if via_file else "refuted"),
            f"env var {mirror_key}: {len(via_env)} mirror requests, {len(tunnels)} CONNECTs, "
            f"Gemfile.lock keeps remote https://rubygems.org/={remote_kept}; config file in BUNDLE_APP_CONFIG "
            f"with BUNDLE_IGNORE_CONFIG=1: rc={r_file['rc']} mirror requests={len(via_file)}")

    # Today's `bundle add` and `bundle update` install what they resolve
    # (gem downloads, and native-extension builds for gems that have them).
    # The lock-only forms: `bundle add --skip-install` and `bundle lock --update`.
    installed = [e for label in ("ruby-add", "ruby-update") for e in s.requests(label)
                 if e.get("path", "").endswith(".gem")]
    d3 = s.scenario_dir("ruby-lock-only-edits", {"Gemfile": RUBY_GEMFILE})
    runs = [s.run("ruby-lock-only-base", [bundle, "lock"], env_for(d3), d3, d3),
            s.run("ruby-add-skip-install", [bundle, "add", "rainbow", "--skip-install"], env_for(d3), d3, d3),
            s.run("ruby-lock-update", [bundle, "lock", "--update"], env_for(d3), d3, d3),
            s.run("ruby-lock-update-gem", [bundle, "lock", "--update", "rainbow"], env_for(d3), d3, d3)]
    fetched = [e for label in ("ruby-lock-only-base", "ruby-add-skip-install", "ruby-lock-update",
                               "ruby-lock-update-gem")
               for e in s.requests(label) if e.get("path", "").endswith(".gem")]
    gem_dir = os.path.join(d3, ".spike", "gems", "gems")
    on_disk = sorted(os.listdir(gem_dir)) if os.path.isdir(gem_dir) else []
    with open(os.path.join(d3, "Gemfile.lock")) as handle:
        locked = "rainbow (" in handle.read()
    s.claim("bundler-lock-only-edits",
            "confirmed" if all(r["rc"] == 0 for r in runs) and not fetched and not on_disk and locked
            else "refuted",
            f"today's bundle add/update downloaded {sorted({e['path'] for e in installed})}; "
            f"add --skip-install + lock --update: rc={[r['rc'] for r in runs]}, .gem downloads={len(fetched)}, "
            f"installed gems={on_disk}, rainbow locked={locked}")


def extract_ruby_helper():
    source = open(os.path.join(REPO, "src", "tailors", "ruby", "mod.rs")).read()
    start = source.index('const HELPER: &str = r##"') + len('const HELPER: &str = r##"')
    return source[start:source.index('"##;', start)]


def census_elixir(s):
    beam = s.obj("*-beam-*")
    mix = os.path.join(beam, "elixir", "bin", "mix")

    def env_for(scenario, mirror=True):
        spike = os.path.join(scenario, ".spike")
        env = s.base_env(scenario, [os.path.join(beam, "elixir", "bin"), os.path.join(beam, "otp", "bin")])
        env.update({
            "MIX_DEPS_PATH": os.path.join(spike, "deps"), "MIX_ARCHIVES": os.path.join(beam, "archives"),
            "MIX_REBAR3": os.path.join(beam, "rebar3"), "MIX_HOME": os.path.join(spike, "mix"),
            "HEX_HOME": os.path.join(spike, "hex"), "MIX_TARGET": "host",
            "HEX_HTTP_PROXY": s.proxy_url, "HEX_HTTPS_PROXY": s.proxy_url,
            "HEX_CACERTS_PATH": s.ca,
        })
        if mirror:
            env["HEX_MIRROR"] = s.mirror("hex").rstrip("/")
        env.update(git_env(s))
        return env

    mix_exs = ('defmodule Spike.MixProject do\n  use Mix.Project\n  def project do\n'
               '    [app: :spike, version: "0.1.0", deps: [{:jason, "~> 1.4"}]]\n  end\nend\n')
    d = s.scenario_dir("elixir-unix-probe", {"mix.exs": mix_exs})
    r = s.run("elixir-unix-probe", [mix, "deps.get"], env_for(d), d, d, allow_unix=True)
    s.claim("elixir-af-unix-targets", "observed",
            f"with AF_UNIX allowed: programs {r.get('af_unix_programs')} connect to {r.get('af_unix_connect_paths')}")
    d = s.scenario_dir("elixir-edit", {"mix.exs": mix_exs})
    s.run("elixir-missing-lock", [mix, "deps.get"], env_for(d), d, d)
    shutil.rmtree(os.path.join(d, ".spike", "deps"), ignore_errors=True)
    s.run("elixir-planner-check-locked", [mix, "deps.get", "--check-locked"], env_for(d), d, d)
    s.run("elixir-update", [mix, "deps.update", "--all"], env_for(d), d, d)
    before = sha256(os.path.join(d, "mix.lock"))
    shutil.rmtree(os.path.join(d, ".spike", "deps"), ignore_errors=True)
    shutil.rmtree(os.path.join(d, ".spike", "hex"), ignore_errors=True)
    r = s.run("elixir-attest", [mix, "deps.get", "--check-locked"], env_for(d), d, d)
    unchanged = before == sha256(os.path.join(d, "mix.lock"))
    with open(os.path.join(d, "mix.exs"), "w") as handle:
        handle.write(mix_exs.replace('{:jason, "~> 1.4"}', '{:jason, "~> 1.4"}, {:telemetry, "~> 1.2"}'))
    r2 = s.run("elixir-attest-drift", [mix, "deps.get", "--check-locked"], env_for(d), d, d)
    s.claim("attest-mix-check-locked", "confirmed" if r["rc"] == 0 and unchanged and r2["rc"] != 0 else "refuted",
            f"consistent rc={r['rc']} bytes-unchanged={unchanged}; drift rc={r2['rc']} "
            f"({(r2['stderr'] + r2['stdout']).strip()[-200:]!r})")
    mirrored = [e for e in s.requests("elixir-missing-lock") if e.get("dialect") == "mirror:hex"]
    tunnels = [e for e in s.requests("elixir-missing-lock") if e["event"] == "connect"]
    s.claim("hex-mirror", "confirmed" if mirrored and r["rc"] == 0 else "refuted",
            f"HEX_MIRROR: {len(mirrored)} mirror requests, CONNECT tunnels {len(tunnels)} "
            f"({sorted({e['host'] for e in tunnels})})")
    # HEX_HTTPS_PROXY: without the mirror, Hex's own traffic must reach the proxy as CONNECT.
    no_auth = f"http://127.0.0.1:{s.tool_port}"
    hex_variants = {
        "hex-vars-with-token": {},
        "hex-vars-no-userinfo": {"HEX_HTTP_PROXY": no_auth, "HEX_HTTPS_PROXY": no_auth},
        "lowercase-vars-with-token": {"HEX_HTTP_PROXY": None, "HEX_HTTPS_PROXY": None,
                                      "http_proxy": s.proxy_url, "https_proxy": s.proxy_url},
    }
    seen = {}
    for name, changes in hex_variants.items():
        d = s.scenario_dir(f"elixir-proxy-{name}", {"mix.exs": mix_exs})
        env = env_for(d, mirror=False)
        for key, value in changes.items():
            if value is None:
                env.pop(key, None)
            else:
                env[key] = value
        r = s.run(f"elixir-proxy-{name}", [mix, "deps.get"], env, d, d, timeout=180)
        tunnels = [e for e in s.requests(f"elixir-proxy-{name}") if e["event"] == "connect"]
        seen[name] = (r["rc"], sorted({(e["host"], e["auth"]) for e in tunnels}))
    s.claim("hex-http-proxy-vars", "confirmed" if seen["hex-vars-with-token"][1] else "refuted",
            "no HEX_MIRROR; " + "; ".join(f"{k}: rc={v[0]} CONNECTs={v[1]}" for k, v in seen.items()))


def census_dotnet(s):
    sdk = s.obj("*-dotnet-sdk-*")
    dotnet = os.path.join(sdk, "dotnet")

    def env_for(scenario, quiet_ipc=True, revocation_offline=True):
        spike = os.path.join(scenario, ".spike")
        env = s.base_env(scenario, [sdk])
        env.update({
            "DOTNET_ROOT": sdk, "NUGET_PACKAGES": os.path.join(spike, "pkgs"),
            "DOTNET_CLI_TELEMETRY_OPTOUT": "1", "DOTNET_NOLOGO": "1",
            "DOTNET_CLI_HOME": spike, "DOTNET_SKIP_FIRST_TIME_EXPERIENCE": "1",
            "XDG_CONFIG_HOME": os.path.join(spike, "xdg"), "XDG_CACHE_HOME": os.path.join(spike, "xdg-cache"),
            "HTTPS_PROXY": s.proxy_url, "HTTP_PROXY": s.proxy_url,
            "DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE": "1",
        })
        if revocation_offline:
            env["NUGET_CERT_REVOCATION_MODE"] = "offline"
        if quiet_ipc:
            env.update({"DOTNET_EnableDiagnostics": "0", "MSBUILDDISABLENODEREUSE": "1"})
        return env

    def config(scenario, insecure=True):
        path = os.path.join(scenario, ".spike", "nuget.config")
        attr = ' allowInsecureConnections="true"' if insecure else ""
        with open(path, "w") as handle:
            handle.write('<?xml version="1.0" encoding="utf-8"?>\n<configuration><packageSources><clear />'
                         f'<add key="tog" value="{s.mirror("nuget")}v3/index.json" protocolVersion="3"{attr} />'
                         '</packageSources></configuration>\n')
        return path

    csproj = ('<Project Sdk="Microsoft.NET.Sdk">\n  <PropertyGroup>\n    <OutputType>Exe</OutputType>\n'
              '    <TargetFramework>net9.0</TargetFramework>\n'
              '    <RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>\n  </PropertyGroup>\n'
              '  <ItemGroup>\n    <PackageReference Include="Humanizer.Core" Version="2.14.1" />\n'
              '  </ItemGroup>\n</Project>\n')
    files = {"spike.csproj": csproj, "Program.cs": "System.Console.WriteLine(1);\n"}
    quiet = ["--disable-build-servers", "-maxcpucount:1"]
    for label, ipc in (("dotnet-unix-probe", True), ("dotnet-unix-probe-default-ipc", False)):
        d = s.scenario_dir(label, files)
        r = s.run(label, [dotnet, "restore", "--use-lock-file", "--configfile", config(d)] + (quiet if ipc else []),
                  env_for(d, quiet_ipc=ipc), d, d, allow_unix=True)
        s.claim(label.replace("dotnet-unix-probe", "dotnet-af-unix-targets"), "observed",
                f"with AF_UNIX allowed (IPC settings {'on' if ipc else 'off'}): rc={r['rc']} programs "
                f"{r.get('af_unix_programs')} connect to {r.get('af_unix_connect_paths')}")
    d = s.scenario_dir("dotnet-edit", files)
    r = s.run("dotnet-missing-lock", [dotnet, "restore", "--use-lock-file", "--configfile", config(d)] + quiet,
              env_for(d), d, d)
    rewritten = [e for e in s.requests("dotnet-missing-lock") if e.get("rewritten")]
    tunnels = [e for e in s.requests("dotnet-missing-lock") if e["event"] == "connect"]
    s.claim("nuget-mirror-allow-insecure", "confirmed" if r["rc"] == 0 else "refuted",
            f"http mirror source with allowInsecureConnections rc={r['rc']}, rewritten JSON responses "
            f"{len(rewritten)}, CONNECTs {sorted({e['host'] for e in tunnels})}")
    s.claim("dotnet-no-unix-socket-settings", "confirmed" if r["rc"] == 0 else "refuted",
            f"restore under the AF_UNIX filter with DOTNET_EnableDiagnostics=0, MSBUILDDISABLENODEREUSE=1, "
            f"--disable-build-servers, -maxcpucount:1: rc={r['rc']}, AF_UNIX denied {r.get('af_unix_denied')}, "
            f"connect targets {r.get('af_unix_connect_paths')}")
    before = sha256(os.path.join(d, "packages.lock.json"))
    shutil.rmtree(os.path.join(d, ".spike", "pkgs"), ignore_errors=True)
    r = s.run("dotnet-attest", [dotnet, "restore", "--locked-mode", "--configfile", config(d)] + quiet,
              env_for(d), d, d)
    unchanged = before == sha256(os.path.join(d, "packages.lock.json"))
    with open(os.path.join(d, "spike.csproj"), "w") as handle:
        handle.write(csproj.replace("2.14.1", "2.14.0"))
    r2 = s.run("dotnet-attest-drift", [dotnet, "restore", "--locked-mode", "--configfile", config(d)] + quiet,
               env_for(d), d, d)
    s.claim("attest-dotnet-locked-mode", "confirmed" if r["rc"] == 0 and unchanged and r2["rc"] != 0 else "refuted",
            f"consistent rc={r['rc']} bytes-unchanged={unchanged}; drift rc={r2['rc']} "
            f"({(r2['stdout'] + r2['stderr']).strip()[-200:]!r})")

    # Controls: no allowInsecureConnections; revocation online; IPC settings off.
    d = s.scenario_dir("dotnet-secure-only", files)
    r = s.run("dotnet-no-allow-insecure", [dotnet, "restore", "--use-lock-file", "--configfile",
                                           config(d, insecure=False)] + quiet, env_for(d), d, d)
    s.claim("nuget-http-source-needs-allow-insecure", "confirmed" if r["rc"] != 0 else "refuted",
            f"without the attribute rc={r['rc']} ({(r['stdout'] + r['stderr']).strip()[-220:]!r})")
    d = s.scenario_dir("dotnet-revocation-online", files)
    r = s.run("dotnet-revocation-online", [dotnet, "restore", "--use-lock-file", "--configfile", config(d)]
              + quiet, env_for(d, revocation_offline=False), d, d)
    online = [(e.get("host"), e.get("path")) for e in s.requests("dotnet-revocation-online")
              if e.get("dialect") == "forward-http" or e["event"] == "connect"]
    offline = [(e.get("host"), e.get("path")) for e in s.requests("dotnet-missing-lock")
               if e.get("dialect") == "forward-http"]
    s.claim("nuget-cert-revocation-offline", "confirmed" if not offline else "refuted",
            f"revocation offline: plain-http/CONNECT {offline}; online (control) rc={r['rc']}: {online[:6]}")
    d = s.scenario_dir("dotnet-ipc-default", files)
    r = s.run("dotnet-ipc-default", [dotnet, "restore", "--use-lock-file", "--configfile", config(d)],
              env_for(d, quiet_ipc=False), d, d)
    s.claim("dotnet-default-ipc-under-filter", "observed",
            f"restore without the IPC settings under the filter rc={r['rc']}, AF_UNIX denied "
            f"{r.get('af_unix_denied')}, connect targets {r.get('af_unix_connect_paths')}")


def census_git(s):
    git = shutil.which("git") or "/usr/bin/git"

    def env_for(scenario):
        env = s.base_env(scenario, [])
        env.update(git_env(s))
        return env

    d = s.scenario_dir("git-row")
    r = s.run("git-ls-remote", [git, "ls-remote", "https://github.com/dtolnay/itoa", "HEAD"], env_for(d), d, d)
    s.run("git-clone", [git, "clone", "--depth", "1", "https://github.com/dtolnay/itoa",
                        os.path.join(d, "itoa")], env_for(d), d, d)
    ssh = s.run("git-ssh-url-rewritten", [git, "ls-remote", "ssh://git@github.com/dtolnay/itoa", "HEAD"],
                env_for(d), d, d)
    scp = s.run("git-scp-url-rewritten", [git, "ls-remote", "git@github.com:dtolnay/itoa", "HEAD"],
                env_for(d), d, d)
    s.claim("git-insteadof-rewrites-ssh", "confirmed" if ssh["rc"] == 0 and scp["rc"] == 0 else "refuted",
            f"ssh:// rc={ssh['rc']}, scp-style rc={scp['rc']}")
    plain = s.run("git-scheme-refused", [git, "ls-remote", "git://github.com/dtolnay/itoa", "HEAD"],
                  env_for(d), d, d)
    ext = s.run("git-ext-refused", [git, "ls-remote", "ext::sh -c touch% /tmp/pwned", "HEAD"],
                env_for(d), d, d)
    s.claim("git-protocol-allow", "confirmed" if plain["rc"] != 0 and ext["rc"] != 0 and r["rc"] == 0 else "refuted",
            f"https rc={r['rc']}; git:// rc={plain['rc']} ({plain['stderr'].strip()[-80:]!r}); "
            f"ext:: rc={ext['rc']} ({ext['stderr'].strip()[-80:]!r})")
    env = s.base_env(d, [])
    env.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_TERMINAL_PROMPT": "0"})
    direct = s.run("git-cainfo-direct", [git, "-c", f"http.sslCAInfo={s.ca}", "ls-remote",
                                         "https://github.com/dtolnay/itoa", "HEAD"], env, d, d,
                   confined=False, seccomp=False, trace=False)
    control = s.run("git-cainfo-direct-control", [git, "ls-remote", "https://github.com/dtolnay/itoa", "HEAD"],
                    env, d, d, confined=False, seccomp=False, trace=False)
    s.claim("git-sslcainfo-replaces-roots", "confirmed" if direct["rc"] != 0 and control["rc"] == 0 else "refuted",
            f"direct with http.sslCAInfo=tog CA rc={direct['rc']}; without rc={control['rc']}")


def census_bwrap_loopback(s):
    d = s.scenario_dir("bwrap-loopback")
    # /sys is the host's sysfs under --ro-bind / /, so ask the namespace itself.
    r = s.run("bwrap-loopback", ["/usr/bin/ip", "-o", "link"], s.base_env(d, []), d, d,
              seccomp=False, trace=False)
    lines = [line for line in r["stdout"].splitlines() if line.strip()]
    up = len(lines) == 1 and ": lo:" in lines[0] and "UP" in lines[0].split(">")[0]
    s.claim("bwrap-brings-up-loopback", "confirmed" if up else "refuted",
            f"interfaces in the namespace: {lines}")


CENSUS = {
    "bwrap": census_bwrap_loopback,
    "python": census_python,
    "npm": census_npm,
    "pnpm": census_pnpm,
    "cargo": census_cargo,
    "go": census_go,
    "ruby": census_ruby,
    "elixir": census_elixir,
    "dotnet": census_dotnet,
    "git": census_git,
}


# ---------------------------------------------------------------------------
# Report


def normalize(path):
    path = path.split("?")[0]
    path = re.sub(r"/[0-9a-f]{40,}", "/<hash>", path)
    return path


def report(args):
    work = os.path.abspath(args.work)
    entries = [json.loads(line) for line in open(os.path.join(work, "proxy.jsonl"))]
    by_label = {}
    for entry in entries:
        by_label.setdefault(entry.get("label", ""), []).append(entry)
    for label, items in by_label.items():
        print(f"\n### {label}\n")
        print("| dialect | method | host | path | status | location |")
        print("|---|---|---|---|---|---|")
        seen = set()
        for e in items:
            if e["event"] == "connect":
                row = ("CONNECT", "", f"{e['host']}:{e['port']}", f"auth={e['auth']}", str(e.get("status")), "")
            elif e["event"] == "error":
                row = (e.get("dialect", ""), e["method"], e["host"], normalize(e["path"]), "error", e["error"][:60])
            else:
                row = (e["dialect"], e["method"], e["host"], normalize(e["path"]), str(e["status"]),
                       e.get("location", "")[:80])
            if row not in seen:
                seen.add(row)
                print("| " + " | ".join(row) + " |")
    claims_path = os.path.join(work, "claims.jsonl")
    if os.path.exists(claims_path):
        print("\n### claims\n")
        for line in open(claims_path):
            c = json.loads(line)
            print(f"- {c['claim']}: {c['verdict']} — {c['evidence']}")


FIXTURE_LIMIT = 256 * 1024
ECOSYSTEM_OF_PREFIX = {"py": "python", "npm": "npm", "pnpm": "pnpm", "cargo": "cargo", "go": "go",
                       "ruby": "ruby", "elixir": "elixir", "dotnet": "dotnet", "git": "git"}
# Traffic the door turns off, so the fixture registries leave it out.
NOT_FIXTURE = [
    ("registry.npmjs.org", "/npm", "npm's update notifier (the door passes --update-notifier=false)"),
]


def fixtures(args):
    """Curate WORK/record into tests/fixtures/proxy/registry/<ecosystem>/.

    Each body is stored at <host>/<path>.body and listed in index.json. One body per URL (the first recorded), bodies over FIXTURE_LIMIT left out
    but listed with their digest, the compact-index /versions file cut to the
    gems the census used (Bundler checks each line against /info, so a cut
    file stays valid), and the census log copied with the token redacted.
    """
    work = os.path.abspath(args.work)
    record = os.path.join(work, "record")
    out = os.path.abspath(args.out)
    registry = os.path.join(out, "registry")
    if os.path.exists(registry):
        shutil.rmtree(registry)
    indexes = {}
    seen = set()
    gems = set()
    for line in open(os.path.join(record, "index.jsonl")):
        meta = json.loads(line)
        if "/index.rubygems.org/info/" in meta["file"]:
            gems.add(meta["file"].rsplit("/", 1)[1])
    for line in open(os.path.join(record, "index.jsonl")):
        meta = json.loads(line)
        label = meta["file"].split("/", 1)[0]
        ecosystem = ECOSYSTEM_OF_PREFIX.get(label.split("-", 1)[0])
        if ecosystem is None or (ecosystem, meta["method"], meta["url"]) in seen:
            continue
        seen.add((ecosystem, meta["method"], meta["url"]))
        host_path = meta["file"].split("/", 1)[1]
        body = open(os.path.join(record, meta["file"]), "rb").read()
        entry = {"method": meta["method"], "url": meta["url"], "status": meta["status"],
                 "headers": meta["headers"], "sha256": meta["sha256"], "size": len(body), "census_label": label}
        skip = [reason for host, path, reason in NOT_FIXTURE
                if meta["url"] == f"https://{host}{path}"]
        if host_path == "index.rubygems.org/versions":
            head, _, rest = body.partition(b"---\n")
            kept = [row for row in rest.split(b"\n") if row.split(b" ", 1)[0].decode(errors="replace") in gems]
            body = head + b"---\n" + b"\n".join(kept) + b"\n"
            entry["filtered"] = f"cut to the lines for {sorted(gems)}; sha256 and size are the upstream body's"
        if skip:
            entry["omitted"] = skip[0]
        elif len(body) > FIXTURE_LIMIT:
            entry["omitted"] = f"larger than {FIXTURE_LIMIT} bytes"
        else:
            # The suffix keeps a document (`/is-odd`) and the directory under
            # the same URL path (`/is-odd/-/is-odd-3.0.1.tgz`) apart.
            name = host_path + ".body"
            target = os.path.join(registry, ecosystem, name)
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with open(target, "wb") as handle:
                handle.write(body)
            entry["file"] = name
        indexes.setdefault(ecosystem, []).append(entry)
    for ecosystem, entries in indexes.items():
        with open(os.path.join(registry, ecosystem, "index.json"), "w") as handle:
            json.dump(entries, handle, indent=1, sort_keys=True)
            handle.write("\n")
    # Every session draws its own token, so they are found by shape: the
    # proxy userinfo `tog:<token>` and the mirror prefix `/<token>/`.
    tokens = set()
    for name in ("proxy.jsonl", "results.jsonl", "claims.jsonl", "forced.jsonl"):
        source = os.path.join(work, name)
        if os.path.exists(source):
            text = open(source).read()
            tokens.update(re.findall(r"tog:([0-9a-f]{32})@", text))
            tokens.update(re.findall(r"127\.0\.0\.1:\d+/([0-9a-f]{32})/", text))
    store = os.path.abspath(args.store) if args.store else None

    def scrub(text):
        for token in tokens:
            text = text.replace(token, "<token>")
        if store:
            text = text.replace(store, "<store>")
        return text.replace(work, "<work>")

    census = os.path.join(out, "census")
    os.makedirs(census, exist_ok=True)
    with open(os.path.join(census, "requests.jsonl"), "w") as handle:
        for line in open(os.path.join(work, "proxy.jsonl")):
            entry = json.loads(line)
            entry.pop("t", None)
            handle.write(scrub(json.dumps(entry, sort_keys=True)) + "\n")
    for name in ("claims.jsonl", "forced.jsonl"):
        source = os.path.join(work, name)
        if os.path.exists(source):
            with open(os.path.join(census, name), "w") as handle:
                for line in open(source):
                    handle.write(scrub(line))
    with open(os.path.join(census, "runs.jsonl"), "w") as handle:
        for line in open(os.path.join(work, "results.jsonl")):
            r = json.loads(line)
            keep = {k: r[k] for k in ("label", "rc", "confined", "seccomp", "af_unix_attempts", "af_unix_denied",
                                      "io_uring", "af_unix_programs", "io_uring_programs", "argv") if k in r}
            handle.write(scrub(json.dumps(keep, sort_keys=True)) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--work", required=True)
    parser.add_argument("--store")
    parser.add_argument("--mitmdump", default="mitmdump")
    parser.add_argument("--nounix", default="nounix")
    parser.add_argument("--record", action="store_true", help="save upstream bodies under WORK/record")
    parser.add_argument("--engine", choices=["bwrap", "seatbelt"],
                        default="seatbelt" if sys.platform == "darwin" else "bwrap",
                        help="bwrap: Linux confinement with the seccomp filter; seatbelt: macOS Mach measurement")
    parser.add_argument("--verbose", action="store_true")
    sub = parser.add_subparsers(dest="command", required=True)
    census = sub.add_parser("census")
    census.add_argument("ecosystems", nargs="*", default=list(CENSUS))
    forced_parser = sub.add_parser("forced")
    forced_parser.add_argument("tools", nargs="*")
    sub.add_parser("report")
    fixtures_parser = sub.add_parser("fixtures")
    fixtures_parser.add_argument("--out", default=os.path.join(REPO, "tests", "fixtures", "proxy"))
    args = parser.parse_args()
    if args.command == "report":
        report(args)
        return
    if args.command == "fixtures":
        fixtures(args)
        return
    if not args.store:
        parser.error("--store is required")
    sys.path.insert(0, HERE)
    import forced

    table = CENSUS if args.command == "census" else forced.FORCED
    names = (args.ecosystems if args.command == "census" else args.tools) or list(table)
    session = Session(args)
    session.start()
    try:
        for name in names:
            print(f"== {name}", flush=True)
            table[name](session)
    finally:
        session.stop()


if __name__ == "__main__":
    main()

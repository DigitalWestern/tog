"""mitmproxy addon for the resolution-proxy evidence spike (PR 0).

Loaded by `spike.py` into one `mitmdump` listener that speaks both dialects
of docs/agent/DESIGNS.md §6 "Per-ecosystem traffic":

- Forward proxy with TLS interception: `CONNECT host:443` must carry
  `Proxy-Authorization: Basic base64(tog:<token>)`, else 407. mitmproxy
  terminates TLS with its own CA (the spike's stand-in for the per-process
  tog CA) and every inner request is logged. A host in `spike_refuse` gets a
  visible 403 refusal without interception.
- Registry mirror: a plain-HTTP request whose path starts with
  `/<token>/<route>/` is rewritten to the route's upstream over real TLS.
  NuGet's service index and registration JSON are rewritten on the way back
  so resource URLs point at the mirror, as the design plans.

Every request, refusal, and error is appended to `spike_log` as one JSON line
tagged with the label currently in `spike_label_file` (the driver writes the
scenario name there before each run). With `spike_record_dir` set, every
upstream response body is saved for the offline fixture registries.
"""

import base64
import hashlib
import json
import os
import re
import threading
import time
import urllib.parse

from mitmproxy import ctx, http

# route -> (upstream host, path prefix kept upstream)
ROUTES = {
    "go": "proxy.golang.org",
    "hex": "repo.hex.pm",
    "nuget": "api.nuget.org",
    "rubygems": "rubygems.org",
}
# Bundler's compact index lives on index.rubygems.org; gem files on rubygems.org.
RUBYGEMS_INDEX_PATHS = re.compile(r"^/(versions|names|info/[^/]+)$")
_lock = threading.Lock()


def _label():
    path = ctx.options.spike_label_file
    if not path:
        return ""
    try:
        with open(path) as handle:
            return handle.read().strip()
    except OSError:
        return ""


def _log(entry):
    entry["label"] = _label()
    entry["t"] = round(time.time(), 3)
    line = json.dumps(entry, sort_keys=True)
    with _lock:
        with open(ctx.options.spike_log, "a") as handle:
            handle.write(line + "\n")


def _proxy_auth(flow):
    header = flow.request.headers.get("Proxy-Authorization", "")
    if not header:
        return "missing"
    scheme, _, value = header.partition(" ")
    if scheme.lower() != "basic":
        return "bad-scheme:" + scheme
    try:
        user, _, password = base64.b64decode(value).decode().partition(":")
    except ValueError:
        return "bad-encoding"
    if user == "tog" and password == ctx.options.spike_token:
        return "ok"
    return "bad-credentials"


def _refused_hosts():
    return {h.strip() for h in ctx.options.spike_refuse.split(",") if h.strip()}


def _is_mirror(flow):
    return (
        flow.request.scheme == "http"
        and flow.request.host in ("127.0.0.1", "localhost")
        and flow.request.path.startswith("/" + ctx.options.spike_token + "/")
    )


class Spike:
    def load(self, loader):
        loader.add_option("spike_token", str, "", "session token")
        loader.add_option("spike_log", str, "spike.jsonl", "JSON-lines log")
        loader.add_option("spike_label_file", str, "", "file holding the current label")
        loader.add_option("spike_record_dir", str, "", "save upstream bodies here")
        loader.add_option("spike_refuse", str, "", "CONNECT hosts refused without interception")
        loader.add_option("spike_mirror_base", str, "", "mirror base URL for NuGet rewriting")
        loader.add_option("spike_nuget_keep_signatures", str, "no", "keep RepositorySignatures (yes/no)")

    def http_connect(self, flow: http.HTTPFlow):
        auth = _proxy_auth(flow)
        entry = {
            "event": "connect",
            "host": flow.request.host,
            "port": flow.request.port,
            "auth": auth,
            "ua": flow.request.headers.get("User-Agent", ""),
            "client": flow.client_conn.id[:8],
        }
        if auth != "ok":
            flow.response = http.Response.make(
                407,
                b"tog: proxy authentication required\n",
                {"Proxy-Authenticate": 'Basic realm="tog"'},
            )
            entry["status"] = 407
        elif flow.request.host in _refused_hosts() or "*" in _refused_hosts():
            flow.response = http.Response.make(
                403, f"tog: {flow.request.host} is not a permitted endpoint\n".encode()
            )
            entry["status"] = 403
        else:
            entry["status"] = 200
        _log(entry)

    def requestheaders(self, flow: http.HTTPFlow):
        request = flow.request
        if request.method == "CONNECT":
            return
        flow.metadata["spike_original_url"] = request.pretty_url
        if _is_mirror(flow):
            rest = request.path[len(ctx.options.spike_token) + 2 :]
            route, _, tail = rest.partition("/")
            tail = "/" + tail
            upstream = ROUTES.get(route)
            # Go: neither proxy.golang.org nor sum.golang.org answers
            # /sumdb/sum.golang.org/supported with 200 (both 404, measured
            # 2026-09-23), and on a 404 go falls back to contacting
            # sum.golang.org directly. So the proxy answers /supported itself
            # and forwards the rest of /sumdb/sum.golang.org/ to sum.golang.org.
            if route == "fakecargo":
                # A sparse registry that demands authentication, so cargo asks
                # its credential provider (forced-settings fixture).
                if tail == "/config.json":
                    base = f"http://127.0.0.1:{request.port}/{ctx.options.spike_token}/fakecargo"
                    config = {"dl": base + "/dl", "api": base + "/api", "auth-required": True}
                    flow.response = http.Response.make(
                        200, json.dumps(config).encode(), {"Content-Type": "application/json"}
                    )
                else:
                    flow.response = http.Response.make(404, b"")
                flow.metadata["spike_dialect"] = "mirror:fakecargo"
                return
            if route == "go" and tail == "/sumdb/sum.golang.org/supported":
                flow.response = http.Response.make(200, b"", {"Content-Type": "text/plain"})
                flow.metadata["spike_dialect"] = "mirror:go-synthesized"
                return
            if route == "go" and tail.startswith("/sumdb/sum.golang.org/"):
                upstream, tail = "sum.golang.org", tail[len("/sumdb/sum.golang.org") :]
            elif route == "rubygems" and RUBYGEMS_INDEX_PATHS.match(tail.split("?")[0]):
                upstream = "index.rubygems.org"
            if upstream is None:
                flow.response = http.Response.make(404, b"tog: unknown route\n")
                flow.metadata["spike_dialect"] = "mirror-unknown-route"
                return
            flow.metadata["spike_dialect"] = "mirror:" + route
            # Accept-Encoding is dropped so recorded bodies are the identity bytes.
            request.headers.pop("Accept-Encoding", None)
            request.scheme = "https"
            request.port = 443
            request.host = upstream
            request.path = tail
            return
        if request.scheme == "https":
            flow.metadata["spike_dialect"] = "intercept"
            return
        # Plain http:// through the forward proxy (absolute form).
        auth = _proxy_auth(flow)
        flow.metadata["spike_dialect"] = "forward-http"
        flow.metadata["spike_auth"] = auth
        if auth != "ok":
            flow.response = http.Response.make(
                407, b"tog: proxy authentication required\n",
                {"Proxy-Authenticate": 'Basic realm="tog"'},
            )
        elif request.host in _refused_hosts() or "*" in _refused_hosts():
            flow.response = http.Response.make(
                403, f"tog: {request.host} is not a permitted endpoint\n".encode()
            )

    def response(self, flow: http.HTTPFlow):
        if flow.request.method == "CONNECT":
            return
        request, response = flow.request, flow.response
        dialect = flow.metadata.get("spike_dialect", "?")
        body = response.content or b""
        entry = {
            "event": "request",
            "dialect": dialect,
            "method": request.method,
            "host": request.host,
            "path": request.path,
            "status": response.status_code,
            "location": response.headers.get("Location", ""),
            "ctype": response.headers.get("Content-Type", ""),
            "bytes": len(body),
            "ua": request.headers.get("User-Agent", ""),
            "accept": request.headers.get("Accept", ""),
            "client": flow.client_conn.id[:8],
            "http": request.http_version,
            "auth_header": "Authorization" in request.headers,
        }
        if "spike_auth" in flow.metadata:
            entry["proxy_auth"] = flow.metadata["spike_auth"]
        if dialect.startswith("mirror"):
            entry["tool_url"] = flow.metadata.get("spike_original_url", "")
        if ctx.options.spike_record_dir and response.status_code < 500 and flow.server_conn.address:
            entry["recorded"] = self._record(flow, body)
        if dialect == "mirror:nuget" and ctx.options.spike_mirror_base and "json" in entry["ctype"]:
            base = ctx.options.spike_mirror_base.rstrip("/") + "/" + ctx.options.spike_token + "/nuget/"
            if request.path == "/v3/index.json":
                # NuGet refuses a RepositorySignatures resource served over
                # http (NU1301), so the service index drops that resource.
                index = json.loads(body)
                dropped = [r["@type"] for r in index["resources"] if r["@type"].startswith("RepositorySignatures")]
                index["resources"] = [
                    r for r in index["resources"] if not r["@type"].startswith("RepositorySignatures")
                ]
                if dropped and ctx.options.spike_nuget_keep_signatures != "yes":
                    body_out = json.dumps(index, indent=2).encode()
                    entry["dropped"] = dropped
                else:
                    body_out = body
            else:
                body_out = body
            rewritten = body_out.replace(b"https://api.nuget.org/", base.encode())
            if rewritten != body:
                response.content = rewritten
                entry["rewritten"] = True
        _log(entry)

    def error(self, flow: http.HTTPFlow):
        _log(
            {
                "event": "error",
                "method": flow.request.method,
                "host": flow.request.host,
                "path": flow.request.path,
                "error": str(flow.error),
                "dialect": flow.metadata.get("spike_dialect", "?"),
            }
        )

    def _record(self, flow, body):
        request, response = flow.request, flow.response
        path, _, query = request.path.partition("?")
        rel = path.lstrip("/") or "_root"
        if rel.endswith("/"):
            rel += "_index"
        if query:
            rel += "@" + urllib.parse.quote(query, safe="")
        rel = os.path.join(_label() or "_unlabelled", request.host, rel)
        target = os.path.join(ctx.options.spike_record_dir, rel)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "wb") as handle:
            handle.write(body)
        meta = {
            "method": request.method,
            "url": f"https://{request.host}{request.path}",
            "status": response.status_code,
            "headers": {
                k: v
                for k, v in response.headers.items()
                if k.lower()
                in ("content-type", "location", "etag", "last-modified", "cache-control", "x-checksum-sha256")
            },
            "sha256": hashlib.sha256(body).hexdigest(),
            "file": rel,
        }
        with _lock:
            with open(os.path.join(ctx.options.spike_record_dir, "index.jsonl"), "a") as handle:
                handle.write(json.dumps(meta, sort_keys=True) + "\n")
        return rel


addons = [Spike()]

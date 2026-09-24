#!/usr/bin/env python3
"""macOS Mach allow-list measurement for the resolution door (PR 0, §6).

Used two ways:

- as a module by `spike.py --engine seatbelt`, which runs every census
  invocation under `sandbox-exec` with the profile from `profile()`, reads
  the denied `mach-lookup` names from the unified log, allows them, and
  reruns until the tool passes (the smallest passing set);
- as a script, to turn the resulting WORK/mach.jsonl into the table for
  docs/agent/DESIGNS.md §6 and to fail on a forbidden service:

    python3 tools/proxy_spike/mach_report.py WORK

The profile keeps every other operation allowed on purpose: this run
measures Mach lookups only. The network and file rules are the door's own
and are tested by PR 3's named tests.
"""

import datetime
import fnmatch
import json
import os
import re
import subprocess
import sys

# Services that act for the caller outside the sandbox (design, "Mach
# services are denied by default"). A tool whose measured list names one of
# them must be configured off it before its door ships.
FORBIDDEN = [
    "com.apple.coreservices.*",          # LaunchServices (open URLs and apps)
    "com.apple.lsd.*",
    "com.apple.nsurlsessiond*",          # downloads and uploads for the caller
    "com.apple.securityd*",              # credentials
    "com.apple.SecurityServer",
    "com.apple.security.keychain*",      # Keychain services
    "com.apple.security.agent*",
    "com.apple.dnssd.service",           # name resolution (sends names out)
    "com.apple.mDNSResponder*",
    "com.apple.pasteboard*",             # pasteboard
    "com.apple.coreservices.appleevents",  # Apple Events
    "com.apple.ae.*",
]
# Not forbidden, but they do network work for the caller (certificate
# fetches, OCSP): named in the table for review.
REVIEW = ["com.apple.trustd*", "com.apple.networkd*", "com.apple.symptomsd*"]

DENY = re.compile(r"(?P<process>[^\s(]+)\((?P<pid>\d+)\) deny\(\d+\) mach-lookup (?P<service>\S+)")


def profile(allowed, port):
    """The measurement profile: everything allowed except unlisted Mach lookups.

    Later rules win in SBPL, so the allow-list follows the deny.
    """
    rules = ["(version 1)", "(allow default)", "(deny mach-lookup (with report))"]
    if allowed:
        names = " ".join(f'(global-name "{name}")' for name in allowed)
        rules.append(f"(allow mach-lookup {names})")
    return "\n".join(rules) + "\n"


def log_timestamp():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def denials_since(start):
    """Denied mach-lookup names logged by the sandbox since `start`."""
    output = subprocess.run(
        ["/usr/bin/log", "show", "--style", "ndjson", "--start", start,
         "--predicate", 'eventMessage CONTAINS "mach-lookup" AND eventMessage CONTAINS "deny"'],
        capture_output=True, text=True,
    ).stdout
    found = []
    for line in output.splitlines():
        try:
            message = json.loads(line).get("eventMessage", "")
        except ValueError:
            continue
        match = DENY.search(message)
        if match:
            found.append(match.groupdict())
    unique = {(d["process"], d["service"]): d for d in found}
    return sorted(unique.values(), key=lambda d: (d["service"], d["process"]))


def matches(service, patterns):
    return [p for p in patterns if fnmatch.fnmatchcase(service, p)]


def report(work):
    rows = [json.loads(line) for line in open(os.path.join(work, "mach.jsonl"))]
    failed = False
    print("| Census run | rc | Allow-list (smallest passing set) | Denied and tolerated | Review |")
    print("|---|---|---|---|---|")
    for row in rows:
        forbidden = sorted({s for s in row["allowed"] if matches(s, FORBIDDEN)})
        review = sorted({s for s in row["allowed"] if matches(s, REVIEW)})
        failed |= bool(forbidden) or row["rc"] != 0
        allowed = ", ".join(f"`{s}`" for s in row["allowed"]) or "none"
        if forbidden:
            allowed += " **FORBIDDEN: " + ", ".join(forbidden) + "**"
        tolerated = ", ".join(f"`{s}`" for s in row["tolerated_denials"]) or "none"
        print(f"| {row['label']} | {row['rc']} | {allowed} | {tolerated} | {', '.join(review) or ''} |")
    per_tool = {}
    for row in rows:
        per_tool.setdefault(row["label"].split("-")[0], set()).update(row["allowed"])
    print("\nPer-ecosystem union (the list kernel::resolve compiles in):\n")
    for tool, services in sorted(per_tool.items()):
        print(f"- {tool}: " + (", ".join(f"`{s}`" for s in sorted(services)) or "none"))
    return 1 if failed else 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    sys.exit(report(sys.argv[1]))
